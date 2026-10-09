"""Convert specifications, URLs, and JavaScript strings into endpoint records."""

import re
from urllib.parse import urljoin, urlsplit

from .scope import host_in_scope, url_in_scope

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
ROUTE_HINT = re.compile(r"""(?:"|')((?:https?://[^"'<> ]+)?/(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|rest(?:/|$)|oauth(?:/|$)|auth(?:/|$)|rpc(?:/|$))[^"'<> ]{0,300})(?:"|')""", re.I)
ABSOLUTE_URL = re.compile(r"""https?://[^\s"'<>\\]+""", re.I)


def _server_base(document, source_url, roots):
    """Choose the first in-scope documented server, falling back to spec origin."""
    servers = document.get("servers", []) if isinstance(document, dict) else []
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            continue
        candidate = urljoin(source_url, server["url"])
        if url_in_scope(candidate, roots):
            return candidate.rstrip("/")
    # Swagger 2.0 server fields.
    if isinstance(document, dict) and document.get("host"):
        schemes = document.get("schemes") or [urlsplit(source_url).scheme or "https"]
        for scheme in schemes:
            candidate = "{}://{}{}".format(scheme, document["host"], document.get("basePath", ""))
            if url_in_scope(candidate, roots):
                return candidate.rstrip("/")
    parsed = urlsplit(source_url)
    fallback = "{}://{}".format(parsed.scheme, parsed.netloc)
    return fallback if host_in_scope(parsed.hostname, roots) else None


def parse_spec(document, source_url, source_file, roots=None):
    endpoints = []
    roots = roots or [urlsplit(source_url).hostname or ""]
    base_url = _server_base(document, source_url, roots)
    paths = document.get("paths", {}) if isinstance(document, dict) else {}
    if not isinstance(paths, dict):
        return endpoints
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = []
            for parameter in operation.get("parameters", []) or []:
                if isinstance(parameter, dict):
                    params.append({
                        "name": parameter.get("name"),
                        "in": parameter.get("in"),
                        "required": parameter.get("required", False),
                        "schema": parameter.get("schema"),
                    })
            request_body = operation.get("requestBody")
            full_path = str(path)
            endpoint_url = None
            if base_url and full_path.startswith("/") and not full_path.startswith("//"):
                endpoint_url = urljoin(base_url.rstrip("/") + "/", full_path.lstrip("/"))
            elif base_url and full_path.startswith("http"):
                if url_in_scope(full_path, roots):
                    endpoint_url = full_path
            endpoint_host = urlsplit(endpoint_url).hostname.lower() if endpoint_url else (urlsplit(base_url).hostname.lower() if base_url else "")
            endpoints.append({
                "method": method.upper(),
                "path": full_path,
                "url": endpoint_url,
                "host": endpoint_host,
                "summary": operation.get("summary"),
                "operation_id": operation.get("operationId"),
                "tags": operation.get("tags", []),
                "parameters": params,
                "request_body": request_body,
                "responses": sorted(str(key) for key in (operation.get("responses") or {}).keys()),
                "security": operation.get("security", document.get("security", [])),
                "deprecated": bool(operation.get("deprecated", False)),
                "source_type": "openapi",
                "source_url": source_url,
                "source_file": source_file,
                "evidence": "Documented operation; not a verified vulnerability.",
            })
    return endpoints


def extract_url_candidates(urls, roots):
    records = []
    for url, source in urls:
        if not url_in_scope(url, roots):
            continue
        parsed = urlsplit(url)
        path = parsed.path or "/"
        host = parsed.hostname.lower() if parsed.hostname else ""
        if re.search(r"/(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|rest(?:/|$)|oauth(?:/|$)|auth(?:/|$)|rpc(?:/|$))", path, re.I):
            records.append({
                "method": None, "path": path, "url": url, "host": host,
                "summary": None, "operation_id": None, "tags": [],
                "parameters": [], "request_body": None, "responses": [],
                "security": [], "deprecated": False, "source_type": "url",
                "source_url": source, "source_file": None,
                "evidence": "URL candidate from recon output; HTTP method and behavior not verified.",
            })
    return records


def extract_javascript_candidates(source_url, text, roots):
    records = []
    candidates = []
    candidates.extend((value.rstrip(");,]"), "absolute") for value in ABSOLUTE_URL.findall(text))
    candidates.extend((value, "route") for value in ROUTE_HINT.findall(text))
    seen = set()
    for value, kind in candidates:
        url = urljoin(source_url, value)
        if not url_in_scope(url, roots):
            continue
        parsed = urlsplit(url)
        path = parsed.path or "/"
        host = parsed.hostname.lower() if parsed.hostname else ""
        key = (host, path)
        if key in seen:
            continue
        seen.add(key)
        records.append({
            "method": None, "path": path, "url": url, "host": host,
            "summary": None, "operation_id": None, "tags": [],
            "parameters": [], "request_body": None, "responses": [],
            "security": [], "deprecated": False, "source_type": "javascript",
            "source_url": source_url, "source_file": None,
            "evidence": "Route/URL string extracted from JavaScript; not verified.",
        })
    return records
