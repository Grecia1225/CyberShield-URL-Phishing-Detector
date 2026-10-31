"""Optional online lookups: server location, domain age, Google Safe Browsing.
The submitted site itself is never opened. Only DNS, an IP-geolocation service,
the RDAP registry and (optionally) Google Safe Browsing are contacted."""
import ipaddress
import os
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

TIMEOUT = 4
HEADERS = {"User-Agent": "CyberShield-URL-scanner/1.0"}
_pool = ThreadPoolExecutor(max_workers=8)

def _resolve(hostname):
    try:
        return [ipaddress.ip_address(hostname.strip("[]"))]
    except ValueError:
        pass
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return [ipaddress.ip_address(i[4][0]) for i in infos]

def _public_ip(hostname):
    """Return (ip_string or None, status). Never returns private/internal addresses."""
    try:
        ips = _pool.submit(_resolve, hostname).result(timeout=TIMEOUT)
    except Exception:
        return None, "unresolvable"
    for ip in ips:
        if ip.is_global:
            return str(ip), "ok"
    return None, "private"

def _geolocate(ip):
    # ip-api.com free tier is HTTP-only and sends just the IP address (never the URL).
    r = requests.get(f"http://ip-api.com/json/{ip}", headers=HEADERS, timeout=TIMEOUT,
                     params={"fields": "status,country,countryCode,regionName,city,isp,org,as,hosting"})
    d = r.json()
    if d.get("status") != "success":
        return None
    return {"ip": ip, "country": d.get("country"), "country_code": d.get("countryCode"),
            "region": d.get("regionName"), "city": d.get("city"), "isp": d.get("isp"),
            "org": d.get("org"), "asn": d.get("as"), "hosting": d.get("hosting")}

def _domain_age_days(domain):
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None
    r = requests.get(f"https://rdap.org/domain/{domain}", headers=HEADERS, timeout=TIMEOUT)
    if r.status_code != 200:
        return None
    for ev in r.json().get("events", []):
        if ev.get("eventAction") == "registration":
            created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            return max(0, (datetime.now(timezone.utc) - created).days)
    return None

def _safe_browsing(url):
    key = os.environ.get("SAFE_BROWSING_KEY")
    if not key:
        return None  # not configured
    body = {"client": {"clientId": "cybershield", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": url}]}}
    r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                      params={"key": key}, json=body, timeout=TIMEOUT)
    return bool(r.json().get("matches"))

def enrich(hostname, url, reg_domain, is_ip):
    points, reasons, details, force_high = 0, [], {}, False
    ip, status = _public_ip(hostname)
    jobs = {"safe_browsing": _pool.submit(_safe_browsing, url)}
    if ip:
        jobs["location"] = _pool.submit(_geolocate, ip)
    if not is_ip:
        jobs["age"] = _pool.submit(_domain_age_days, reg_domain)

    def get(name):
        try:
            return jobs[name].result(timeout=TIMEOUT + 1) if name in jobs else None
        except Exception:
            return None

    if status == "unresolvable" and not is_ip:
        points += 8
        reasons.append("The domain does not resolve to an IP address (it may be taken down or mistyped).")
    details["resolved_ip"] = ip

    loc = get("location")
    if loc:
        details["location"] = loc
        if loc.get("hosting"):
            details["hosting_note"] = "Hosted in a data centre / cloud provider (normal for most sites)."

    age = get("age")
    details["domain_age_days"] = age
    if age is not None:
        if age < 30:
            points += 30
            reasons.append(f"The domain was registered only {age} day(s) ago; new domains are common in phishing.")
        elif age < 90:
            points += 20
            reasons.append(f"The domain is only {age} days old.")
        elif age < 365:
            points += 8
            reasons.append(f"The domain is less than a year old ({age} days).")

    sb = get("safe_browsing")
    details["safe_browsing"] = {None: "not checked", True: "flagged", False: "no match"}[sb]
    if sb:
        points += 60
        force_high = True
        reasons.append("Google Safe Browsing lists this URL as dangerous.")
    return {"points": points, "reasons": reasons, "details": details, "force_high": force_high}
