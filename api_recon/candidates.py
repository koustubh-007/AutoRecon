"""Create editable API-host candidates from existing general recon results."""

import os
import re
from urllib.parse import urlsplit

from .scope import normalize_host, host_in_scope

API_LABEL = re.compile(r"^(?:api|api[-_].*|.*[-_]api|graphql|graph|gateway|api[0-9]+|services?)$", re.I)
API_PATH = re.compile(r"/(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|rest(?:/|$)|rpc(?:/|$))", re.I)


def generate_api_candidates(domain, output_dir=None):
    """Write api_candidates.txt and initialize api.domains.txt only if absent.

    Existing user edits to api.domains.txt are intentionally preserved.
    """
    output_dir = output_dir or domain
    os.makedirs(output_dir, exist_ok=True)
    all_subdomains = os.path.join(domain, "all_subdomains.txt")
    all_urls = os.path.join(domain, "all_urls.txt")
    candidates = set()

    if os.path.isfile(all_subdomains):
        with open(all_subdomains, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                host = normalize_host(line)
                if not host or not host_in_scope(host, [normalize_host(domain)]):
                    continue
                labels = host.split(".")
                if any(API_LABEL.fullmatch(label) for label in labels[:-2] if len(labels) > 2) or API_LABEL.fullmatch(labels[0]):
                    candidates.add(host)

    if os.path.isfile(all_urls):
        with open(all_urls, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                url = line.strip()
                try:
                    parsed = urlsplit(url)
                    host = normalize_host(parsed.hostname or "")
                except ValueError:
                    continue
                if host and host_in_scope(host, [normalize_host(domain)]) and API_PATH.search(parsed.path or ""):
                    candidates.add(host)

    candidate_path = os.path.join(output_dir, "api_candidates.txt")
    with open(candidate_path, "w", encoding="utf-8") as handle:
        handle.write("".join(host + "\n" for host in sorted(candidates)))

    selected_path = os.path.join(output_dir, "api.domains.txt")
    if not os.path.exists(selected_path):
        with open(selected_path, "w", encoding="utf-8") as handle:
            handle.write("".join(host + "\n" for host in sorted(candidates)))

    return sorted(candidates)
