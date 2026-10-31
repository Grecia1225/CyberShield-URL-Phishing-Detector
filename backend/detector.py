"""Explainable URL risk heuristics. Offline: this module makes no network calls."""
from urllib.parse import urlsplit, unquote
import ipaddress
import re

SUSPICIOUS_WORDS = {
    "login", "signin", "sign-in", "verify", "verification", "password",
    "account", "secure", "update", "wallet", "billing", "invoice",
    "payment", "recover", "confirm", "authentication", "gift", "bonus",
    "free", "unlock", "webscr", "banking",
}
# brand -> its genuine domains. Anything else containing the brand name is suspicious.
OFFICIAL_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "youtube.com", "googleapis.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "icu", "cfd", "sbs", "buzz", "rest", "monster",
    "gq", "tk", "ml", "ga", "cf", "zip", "mov", "work", "support",
}
TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.au", "com.br", "co.jp", "co.za", "com.cn",
}

def registered_domain(hostname: str) -> str:
    labels = hostname.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def label_for(score: int) -> str:
    return "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW RISK"

def _looks_random(label: str) -> bool:
    label = label.replace("-", "")
    if len(label) < 5 or label.isdigit():
        return False
    vowels = sum(c in "aeiou" for c in label)
    return vowels / len(label) <= 0.2 or bool(re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", label))

def _normalise_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if len(value) > 4096:
        raise ValueError("URL is too long (maximum 4096 characters).")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    return value

def analyze_url(raw_url: str) -> dict:
    """Return a bounded risk score and reasons. This is not a reputation verdict."""
    url = _normalise_url(raw_url)
    try:
        parts = urlsplit(url)
        hostname = (parts.hostname or "").lower().rstrip(".")
        _ = parts.port  # raises ValueError on malformed ports
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs can be scanned.")
    if not hostname or any(ch.isspace() for ch in hostname):
        raise ValueError("The URL must contain a valid hostname.")

    score, reasons = 0, []
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    is_ip = False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
        add(25, "The hostname is an IP address rather than a typical domain name.")
    except ValueError:
        pass

    if parts.scheme.lower() != "https":
        add(8, "The URL uses HTTP rather than HTTPS; this alone does not prove phishing.")
    if "@" in parts.netloc:
        add(25, "The URL contains '@', which can disguise the actual destination.")
    if "xn--" in hostname:
        add(20, "The hostname contains punycode, which can be used in look-alike domains.")
    if len(url) > 120:
        add(10, "The URL is unusually long.")
    if len(hostname) > 45:
        add(10, "The hostname is unusually long.")

    labels = hostname.split(".")
    reg_domain = hostname if is_ip else registered_domain(hostname)
    if len(labels) >= 5:
        add(12, "The hostname contains many subdomain levels.")
    if hostname in SHORTENER_HOSTS:
        add(12, "The URL uses a known URL-shortening domain, hiding the final destination.")

    if not is_ip:
        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            add(10, f"The '.{tld}' top-level domain is frequently abused for throwaway sites.")
        reg_label = reg_domain.split(".")[0]
        if _looks_random(reg_label):
            add(10, f"The domain name '{reg_label}' looks randomly generated.")

    path_query = (parts.path or "") + "?" + (parts.query or "")
    decoded = unquote(path_query).lower()
    found_words = sorted(w for w in SUSPICIOUS_WORDS if w in decoded or w in hostname)
    if found_words:
        add(min(24, 6 + 3 * (len(found_words) - 1)),
            "Contains phishing-associated terms: " + ", ".join(found_words[:8]) + ".")
    if re.search(r"[0-9a-f]{20,}", decoded):
        add(6, "The path contains a long random-looking hex string (typical of generated phishing links).")

    # Brand name in the hostname, but the domain is not one of that brand's real domains.
    brand_hits = sorted(
        b for b, doms in OFFICIAL_DOMAINS.items()
        if b in hostname and not any(hostname == d or hostname.endswith("." + d) for d in doms)
    )
    if brand_hits:
        add(25, "A well-known brand name appears inside a different domain: " + ", ".join(brand_hits[:4]) + ".")

    if re.search(r"\d{5,}", hostname):
        add(8, "The hostname contains a long run of digits.")
    if hostname.count("-") >= 3:
        add(8, "The hostname contains several hyphens.")
    if parts.username or parts.password:
        add(25, "The URL embeds user-information before the hostname.")

    score = min(100, score)
    if not reasons:
        reasons.append("No strong warning signs were found by these basic checks; this is not proof that the site is safe.")

    return {
        "input_url": raw_url,
        "normalized_url": url,
        "hostname": hostname,
        "registered_domain": reg_domain,
        "is_ip": is_ip,
        "label": label_for(score),
        "risk_score": score,
        "reasons": reasons,
        "disclaimer": "Heuristic result only. No detector can guarantee a URL is safe.",
    }
