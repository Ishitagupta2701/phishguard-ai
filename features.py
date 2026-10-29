"""URL feature extraction + human-readable risk reasons."""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "password", "wallet", "suspend", "unlock", "billing", "invoice",
    "paypal", "support", "alert", "recover", "validate", "webscr",
]
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "zip",
    "country", "loan", "support", "rest", "icu", "cam",
}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "num_dots", "num_hyphens",
    "num_digits", "digit_ratio", "num_subdomains", "has_ip", "has_at",
    "has_https", "has_port", "num_params", "double_slash_in_path",
    "suspicious_word_count", "suspicious_tld", "is_shortener", "has_punycode",
    "host_entropy", "hyphen_in_host", "num_special_chars",
]


def normalize(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _parts(url: str):
    parsed = urlparse(normalize(url))
    host = (parsed.hostname or "").lower()
    labels = host.split(".") if host else []
    tld = labels[-1] if labels else ""
    return parsed, host, labels, tld


def extract_features(url: str) -> dict:
    full = normalize(url)
    parsed, host, labels, tld = _parts(url)
    path_q = parsed.path + ("?" + parsed.query if parsed.query else "")
    lowered = full.lower()
    digits = sum(c.isdigit() for c in full)
    registered = ".".join(labels[-2:]) if len(labels) >= 2 else host

    return {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(path_q),
        "num_dots": full.count("."),
        "num_hyphens": full.count("-"),
        "num_digits": digits,
        "digit_ratio": digits / max(len(full), 1),
        "num_subdomains": max(len(labels) - 2, 0),
        "has_ip": int(bool(IP_RE.match(host))),
        "has_at": int("@" in full),
        "has_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None) if _safe_port(parsed) else 1,
        "num_params": len([p for p in parsed.query.split("&") if p]),
        "double_slash_in_path": int("//" in parsed.path),
        "suspicious_word_count": sum(w in lowered for w in SUSPICIOUS_WORDS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(registered in SHORTENERS),
        "has_punycode": int("xn--" in host),
        "host_entropy": _entropy(host),
        "hyphen_in_host": int("-" in host),
        "num_special_chars": sum(not c.isalnum() for c in full),
    }


def _safe_port(parsed) -> bool:
    try:
        parsed.port
        return True
    except ValueError:
        return False


def feature_vector(url: str) -> list:
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]


def explain(url: str) -> list:
    """Return plain-English reasons why a URL looks suspicious."""
    f = extract_features(url)
    reasons = []
    if f["has_ip"]:
        reasons.append("Uses a raw IP address instead of a domain name")
    if f["has_at"]:
        reasons.append("Contains '@' which can hide the real destination")
    if not f["has_https"]:
        reasons.append("Does not use HTTPS")
    if f["num_subdomains"] >= 3:
        reasons.append(f"Has {f['num_subdomains']} subdomains (often used to imitate brands)")
    if f["suspicious_word_count"] >= 2:
        reasons.append(f"Contains {f['suspicious_word_count']} phishing-style keywords (login, verify, secure...)")
    if f["suspicious_tld"]:
        reasons.append("Uses a top-level domain commonly abused by phishers")
    if f["is_shortener"]:
        reasons.append("Uses a URL shortener that hides the final destination")
    if f["has_punycode"]:
        reasons.append("Contains punycode (possible look-alike characters)")
    if f["url_length"] > 75:
        reasons.append(f"Very long URL ({f['url_length']} characters)")
    if f["num_hyphens"] >= 3:
        reasons.append("Many hyphens in the URL")
    if f["double_slash_in_path"]:
        reasons.append("Has '//' inside the path (redirect trick)")
    if f["has_port"]:
        reasons.append("Uses a non-standard port")
    if f["digit_ratio"] > 0.25:
        reasons.append("Unusually high proportion of digits")
    return reasons
