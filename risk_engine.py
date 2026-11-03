"""Explainable URL, domain and webpage risk signals for WebShield."""
from difflib import SequenceMatcher
import ipaddress
import re
from urllib.parse import urlparse

from utils import normalize_url, get_domain

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "bank",
    "payment", "password", "update", "confirm", "signin", "authenticate",
]
SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "work", "click", "top", "zip"}
BRAND_MARKERS = {
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "linkedin", "github", "openai", "bit-bangalore",
}


def _safe_int(value, default=0):
    try:
        return max(0, min(int(value), 100000))
    except (TypeError, ValueError, OverflowError):
        return default


def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except (ValueError, TypeError):
        return False


def _looks_like_trusted_domain(domain, known_domains):
    """Flag close spellings of trusted domains; never treat them as trusted."""
    host = (domain or "").lower().strip(".")
    if not host:
        return None
    best = None
    best_ratio = 0.0
    for trusted in known_domains:
        trusted = str(trusted).lower().strip().removeprefix("www.").strip(".")
        if not trusted or host == trusted or host.endswith("." + trusted):
            continue
        ratio = SequenceMatcher(None, host, trusted).ratio()
        # Catch common one-character substitutions/omissions without
        # marking merely shared suffixes (e.g. example.com vs google.com).
        if ratio > best_ratio:
            best_ratio, best = ratio, trusted
    if best and best_ratio >= 0.78 and abs(len(host) - len(best)) <= 3:
        return best
    return None


def calculate_url_risk(url):
    """Calculate transparent structural indicators from the normalized URL."""
    normalized = normalize_url(url)
    if not normalized:
        return 100, ["URL is empty or invalid"]

    parsed = urlparse(normalized)
    domain = get_domain(normalized)
    score = 0
    reasons = []

    if len(normalized) > 120:
        score += 20
        reasons.append("URL is unusually long (over 120 characters)")
    elif len(normalized) > 75:
        score += 15
        reasons.append("URL is unusually long")
    elif len(normalized) > 50:
        score += 8
        reasons.append("URL is longer than usual")

    hyphens = domain.count("-")
    # A single hyphen is common in legitimate names (including BIT's domain),
    # so only a repeated-hyphen pattern contributes to URL structural risk.
    if hyphens >= 3:
        score += 15
        reasons.append("Hostname contains multiple hyphens")
    elif hyphens >= 2:
        score += 8
        reasons.append("Hostname contains repeated hyphens")

    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in normalized]
    if len(found_keywords) >= 3:
        score += 20
        reasons.append("Multiple phishing-related terms appear in the URL")
    elif found_keywords:
        score += 10
        reasons.append("Phishing-related term appears in the URL")

    # Subdomain count is based on hostname only, not path/query dots.
    labels = [part for part in domain.split(".") if part]
    if len(labels) >= 6:
        score += 15
        reasons.append("Hostname has an unusually deep subdomain structure")
    elif len(labels) >= 5:
        score += 8
        reasons.append("Hostname has several subdomain labels")

    if _is_ip(domain):
        score += 20
        reasons.append("Website uses an IP address instead of a normal domain name")

    if "@" in parsed.netloc:
        score += 25
        reasons.append("URL contains user-info syntax that can disguise the destination")

    if "xn--" in domain:
        score += 20
        reasons.append("Hostname contains an internationalized/punycode label; verify the displayed domain")

    if parsed.scheme != "https":
        score += 8
        reasons.append("URL uses HTTP rather than HTTPS")

    return min(score, 100), reasons


def calculate_domain_risk(domain, known_domains):
    """Score domain familiarity and suspicious hostname patterns."""
    domain = str(domain or "").lower().strip().removeprefix("www.").strip(".")
    if not domain:
        return 100, True, ["Domain could not be extracted"]

    trusted_roots = [str(d).lower().strip().removeprefix("www.").strip(".") for d in known_domains]
    for trusted in trusted_roots:
        if domain == trusted:
            return 0, False, [f"Hostname exactly matches configured trusted domain: {trusted}"]

    score = 15
    reasons = ["Domain is not an exact match for a configured trusted hostname"]
    if any(domain.endswith("." + trusted) for trusted in trusted_roots):
        reasons.append("Subdomain is not automatically trusted; subdomains can be misconfigured or compromised")
    labels = [label for label in domain.split(".") if label]

    if "xn--" in domain:
        score += 25
        reasons.append("Punycode hostname can be used in lookalike-domain attacks")

    if _is_ip(domain):
        score += 20
        reasons.append("Domain field is an IP address")

    if domain.count("-") >= 2:
        score += 12
        reasons.append("Hostname contains multiple hyphens")
    elif "-" in domain:
        score += 5
        reasons.append("Hostname contains a hyphen")

    if len(labels) >= 5:
        score += 10
        reasons.append("Hostname has many labels/subdomains")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Top-level domain .{tld} is commonly associated with elevated abuse in some datasets")

    lookalike = _looks_like_trusted_domain(domain, trusted_roots)
    if lookalike:
        score += 35
        reasons.append(f"Hostname closely resembles trusted domain {lookalike}; spelling is not an exact match")

    # Brand text in a different hostname is a common deception pattern.
    for brand in BRAND_MARKERS:
        if brand in domain and not any(domain == root for root in trusted_roots):
            score += 15
            reasons.append(f"Hostname contains brand-like text ({brand}) outside its trusted domain")
            break

    return min(score, 100), True, reasons


def calculate_page_risk(page_analysis):
    """Return None when no browser DOM telemetry was supplied (not zero risk)."""
    if not isinstance(page_analysis, dict) or not page_analysis:
        return None, []

    score = 0
    reasons = []
    forms = _safe_int(page_analysis.get("forms", 0))
    password_fields = _safe_int(page_analysis.get("password_fields", 0))
    iframes = _safe_int(page_analysis.get("iframes", 0))
    external_links = _safe_int(page_analysis.get("external_links", 0))
    external_form_actions = _safe_int(page_analysis.get("external_form_actions", 0))
    https = bool(page_analysis.get("https", True))

    if password_fields:
        score += 12
        reasons.append("Page contains password input fields (contextual signal, not proof of phishing)")
    if forms >= 3:
        score += 8
        reasons.append("Page contains multiple forms")
    if external_form_actions:
        score += 30
        reasons.append("A form submits data to a different hostname")
    if iframes >= 3:
        score += 8
        reasons.append("Page contains multiple iframes")
    if external_links >= 15:
        score += 5
        reasons.append("Page contains many external links")
    if not https:
        score += 15
        reasons.append("Page is not using HTTPS")

    return min(score, 100), reasons


def calculate_final_risk(ml_probability, dl_probability, url_risk, domain_risk, page_risk, trusted_domain=False):
    """Combine independent signals; reweight when page telemetry is unavailable."""
    ml_score = float(ml_probability) * 100
    dl_score = float(dl_probability) * 100
    model_score = 0.5 * ml_score + 0.5 * dl_score
    page_available = page_risk is not None

    if page_available:
        final_score = 0.30 * model_score + 0.25 * float(url_risk) + 0.15 * float(domain_risk) + 0.30 * float(page_risk)
        page_score_for_breakdown = round(float(page_risk), 2)
        weights_used = {"model": 30, "url": 25, "domain": 15, "page": 30}
    else:
        # Don't award a site a zero page-risk score when page data was never collected.
        total = 0.30 + 0.25 + 0.15
        final_score = (0.30 / total) * model_score + (0.25 / total) * float(url_risk) + (0.15 / total) * float(domain_risk)
        page_score_for_breakdown = None
        weights_used = {"model": round(0.30 / total * 100, 2), "url": round(0.25 / total * 100, 2), "domain": round(0.15 / total * 100, 2), "page": None}

    # Conservative false-positive mitigation for configured official domains.
    # Strong URL/page warnings are never suppressed by this safeguard.
    trusted_domain_adjustment = False
    if trusted_domain and float(url_risk) <= 5 and float(domain_risk) == 0 and (not page_available or float(page_risk) <= 5):
        if final_score > 20:
            trusted_domain_adjustment = True
        final_score = min(final_score, 20)

    final_score = min(max(final_score, 0), 100)
    breakdown = {
        "ml_score": round(ml_score, 2),
        "dl_score": round(dl_score, 2),
        "model_score": round(model_score, 2),
        "url_risk": round(float(url_risk), 2),
        "domain_risk": round(float(domain_risk), 2),
        "page_risk": page_score_for_breakdown,
        "page_analysis_available": page_available,
        "weights_used": weights_used,
        "trusted_domain": bool(trusted_domain),
        "trusted_domain_adjustment": trusted_domain_adjustment,
    }
    return round(final_score, 2), breakdown
