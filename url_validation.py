"""Strict, dependency-light validation and canonicalization for WebShield URLs."""
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def _is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _valid_hostname(host):
    if host == "localhost" or _is_ip_address(host):
        return True
    # Reject malformed dotted-quad-looking values rather than treating them as DNS names.
    if re.fullmatch(r"[0-9.]+", host):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    return all(
        label and len(label) <= 63 and _LABEL_RE.fullmatch(label) is not None
        for label in labels
    )


def validate_url(value):
    """Return (canonical_http_url, None) or (None, human_readable_error).

    The scheme and hostname are canonicalized, but path/query casing is preserved.
    The function never makes a network request.
    """
    raw = str(value or "").strip()
    if not raw:
        return None, "URL is required"
    if len(raw) > 4096:
        return None, "URL is too long (maximum 4096 characters)"
    if _CONTROL_OR_SPACE_RE.search(raw):
        return None, "URL must not contain spaces or control characters"
    if _SCHEME_RE.match(raw) and not raw.lower().startswith(("http://", "https://")):
        return None, "Only HTTP and HTTPS URLs are supported"

    candidate = raw if raw.lower().startswith(("http://", "https://")) else "https://" + raw
    try:
        parsed = urlparse(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None, "Enter a valid HTTP or HTTPS URL, such as example.com"
        if parsed.username is not None or parsed.password is not None:
            return None, "URLs containing embedded usernames or passwords are not accepted"
        port = parsed.port  # raises ValueError for malformed ports
        if port is not None and not 1 <= port <= 65535:
            return None, "URL port is outside the valid range"

        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if not hostname or len(hostname) > 253 or not _valid_hostname(hostname):
            return None, "Hostname contains invalid characters or labels"
        if ":" in hostname:  # IPv6 authority must be bracketed.
            authority = f"[{hostname}]"
        else:
            authority = hostname
        if port is not None:
            authority += f":{port}"
        canonical = urlunparse((scheme, authority, parsed.path or "", parsed.params, parsed.query, parsed.fragment))
        return canonical, None
    except (ValueError, UnicodeError):
        return None, "URL is malformed. Check the hostname and port."
