import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "update",
    "confirm",
    "bank",
    "free",
    "prize",
    "winner",
]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
]


def analyze_url(url):
    reasons = []
    score = 0

    # Add HTTP if the user did not enter a protocol
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Check HTTPS
    if parsed.scheme.lower() != "https":
        reasons.append("Uses HTTP instead of HTTPS")
        score += 2

    # Check for IP address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        reasons.append("Uses an IP address instead of a domain name")
        score += 3

    # Check @ symbol
    if "@" in url:
        reasons.append("Contains an @ symbol, which can hide the real destination")
        score += 3

    # Check URL length
    if len(url) > 100:
        reasons.append("URL is unusually long")
        score += 1

    # Check suspicious keywords
    url_lower = url.lower()
    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            found_keywords.append(keyword)

    if found_keywords:
        reasons.append(
            "Contains suspicious keyword(s): " + ", ".join(found_keywords)
        )
        score += min(len(found_keywords), 3)

    # Check URL shorteners
    if hostname.lower() in SHORTENERS:
        reasons.append("Uses a URL shortening service")
        score += 2

    # Check excessive subdomains
    if len(hostname.split(".")) > 4:
        reasons.append("Contains an unusually large number of subdomains")
        score += 2

        # Keep score within 0-10
    score = min(score, 10)

    # Decide final result
    if score >= 5:
        result = "Potentially Malicious"
    elif score >= 2:
        result = "Suspicious"
    else:
        result = "Looks Safe"

    return {
        "url": url,
        "result": result,
        "score": score,
        "reasons": reasons
    }