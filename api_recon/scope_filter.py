"""Filter enumerated hostnames using a user-supplied out-of-scope list."""

from .scope import normalize_host


def load_out_of_scope(path):
    """Load excluded domains; supports comments, URLs, and leading wildcard dots."""
    excluded = set()
    if not path:
        return excluded
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            value = value.removeprefix("*.").removeprefix(".")
            host = normalize_host(value)
            if host:
                excluded.add(host)
    return excluded


def is_out_of_scope(host, excluded_domains):
    """True for an exact excluded domain or any true subdomain of it."""
    normalized = normalize_host(host)
    if not normalized:
        return False
    return any(
        normalized == excluded or normalized.endswith("." + excluded)
        for excluded in excluded_domains
    )


def filter_subdomains(subdomains, excluded_domains):
    """Return sorted, unique valid hostnames not covered by exclusions."""
    kept = set()
    for raw in subdomains:
        host = normalize_host(raw)
        if host and not is_out_of_scope(host, excluded_domains):
            kept.add(host)
    return sorted(kept)
