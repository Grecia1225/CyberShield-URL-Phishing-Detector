"""Explainable, offline URL risk heuristics. No URL is fetched by this module."""
from urllib.parse import urlsplit, unquote
import ipaddress
import re

SUSPICIOUS_WORDS = {
    "login", "signin", "sign-in", "verify", "verification", "password",
    "account", "secure", "update", "wallet", "billing", "invoice",
    "payment", "recover", "confirm", "authentication", "gift", "bonus",
    "free", "unlock", "webscr", "banking",
}
BRAND_WORDS = {
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "coinbase", "binance",
}
SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "shorturl.at",
}

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
        # Accessing .port can raise ValueError for malformed ports.
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs can be scanned.")
    if not hostname or any(ch.isspace() for ch in hostname):
        raise ValueError("The URL must contain a valid hostname.")

    score = 0
    reasons = []
    def add(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    try:
        ipaddress.ip_address(hostname.strip("[]"))
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
    if len(labels) >= 5:
        add(12, "The hostname contains many subdomain levels.")
    if hostname in SHORTENER_HOSTS:
        add(12, "The URL uses a known URL-shortening domain, hiding the final destination.")

    decoded = unquote((parts.path or "") + "?" + (parts.query or "")).lower()
    found_words = sorted(word for word in SUSPICIOUS_WORDS if word in decoded or word in hostname)
    if found_words:
        add(min(24, 6 + 3 * (len(found_words) - 1)),
            "Contains phishing-associated terms: " + ", ".join(found_words[:8]) + ".")

    host_without_port = hostname
    brand_hits = sorted(brand for brand in BRAND_WORDS if brand in host_without_port)
    # A brand appearing in a hostname is only a weak signal; legitimate subdomains can exist.
    if brand_hits and not any(host_without_port == b or host_without_port.endswith("." + b) for b in brand_hits):
        add(15, "A well-known brand name appears inside a different hostname: " + ", ".join(brand_hits[:4]) + ".")

    if re.search(r"\d{5,}", hostname):
        add(8, "The hostname contains a long run of digits.")
    if hostname.count("-") >= 3:
        add(8, "The hostname contains several hyphens.")
    if parts.username or parts.password:
        add(25, "The URL embeds user-information before the hostname.")

    score = min(100, score)
    label = "HIGH RISK" if score >= 60 else "SUSPICIOUS" if score >= 30 else "LOW RISK"
    if not reasons:
        reasons.append("No strong warning signs were found by these basic checks; this is not proof that the site is safe.")

    return {
        "input_url": raw_url,
        "normalized_url": url,
        "hostname": hostname,
        "label": label,
        "risk_score": score,
        "reasons": reasons,
        "disclaimer": "Heuristic result only. No detector can guarantee a URL is safe.",
    }
