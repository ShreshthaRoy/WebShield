import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "bank",
    "payment",
    "password",
    "update",
    "confirm",
    "signin",
    "authenticate",
]

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq")


def normalize_url(url: str) -> str:
    """Return a normalized HTTP(S) URL for feature extraction."""
    url = str(url or "").strip().lower()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_domain(url: str) -> str:
    """Extract the hostname without www. or a port."""
    normalized = normalize_url(url)

    if not normalized:
        return ""

    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""

    if hostname.startswith("www."):
        hostname = hostname[4:]

    return hostname.lower()


def extract_features(url: str):
    """
    Extract the 12 numeric URL features used by the Random Forest.

    IMPORTANT:
    The feature order must stay identical during training and inference.
    """
    normalized = normalize_url(url)

    parsed = urlparse(normalized)
    domain = get_domain(normalized)
    path = parsed.path or ""

    # Count dots in the hostname, not the whole URL.
    # This prevents "www.example.com" from looking like a
    # multi-subdomain URL simply because of the www prefix.
    domain_dot_count = domain.count(".")

    special_chars = sum(
        1 for char in normalized
        if char in "@?=&_%"
    )

    keyword_count = sum(
        word in normalized
        for word in SUSPICIOUS_KEYWORDS
    )

    ip_address = int(
        re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            domain
        )
        is not None
    )

    depth = len(
        [part for part in path.split("/") if part]
    )

    domain_parts = [
        part for part in domain.split(".")
        if part
    ]

    # This is a lightweight approximation. It intentionally avoids
    # adding a new dependency such as tldextract.
    subdomain_count = max(
        0,
        len(domain_parts) - 2
    )

    suspicious_tld = int(
        any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    )

    return [
        len(normalized),              # 1 URL length
        len(domain),                  # 2 domain length
        domain_dot_count,             # 3 hostname dots
        normalized.count("-"),        # 4 hyphens
        special_chars,                # 5 special characters
        int(parsed.scheme == "https"),# 6 HTTPS
        keyword_count,                # 7 suspicious keywords
        ip_address,                   # 8 IP address
        int("@" in normalized),       # 9 @ symbol
        depth,                         # 10 URL depth
        subdomain_count,              # 11 subdomains
        suspicious_tld,                # 12 suspicious TLD
    ]
