"""Input normalization and explicit target-scope checks."""

import re
from urllib.parse import urlsplit


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\."
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$"
)


def normalize_host(value):
    """Return a normalized hostname, or None for malformed input."""
    value = (value or "").strip()
    if not value or value.startswith("#"):
        return None
    candidate = value if "://" in value else "//" + value
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not _HOST_RE.fullmatch(host):
        return None
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        return None
    return host


def read_host_file(path):
    """Read one hostname per line, ignoring blank lines and comments."""
    hosts = []
    invalid = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw in enumerate(handle, 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            host = normalize_host(value)
            if host:
                hosts.append(host)
            else:
                invalid.append({"line": line_number, "value": value})
    return sorted(set(hosts)), invalid


def host_in_scope(host, roots):
    """Match an exact root or a subdomain of an explicitly supplied root."""
    host = normalize_host(host)
    if not host:
        return False
    for root in roots:
        root = normalize_host(root)
        if root and (host == root or host.endswith("." + root)):
            return True
    return False


def url_in_scope(url, roots):
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    return host_in_scope(host, roots)
