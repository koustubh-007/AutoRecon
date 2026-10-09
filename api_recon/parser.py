"""Convert specifications, URLs, and JavaScript strings into endpoint records."""

import re
from urllib.parse import urljoin, urlsplit

from .scope import url_in_scope

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
ROUTE_HINT = re.compile(r"""(?:"|')((?:https?://[^"'<> ]+)?/(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|rest(?:/|$)|oauth(?:/|$)|auth(?:/|$)|rpc(?:/|$))[^"'<> ]{0,300})(?:"|')""", re.I)
ABSOLUTE_URL = re.compile(r"""https?://[^\s"'<>\\]+""", re.I)


def parse_spec(document, source_url, source_file):
    endpoints = []
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
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "url": urljoin(source_url, path.lstrip("/")) if path.startswith("http") else None,
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
                "method": None,
                "path": path,
                "url": url,
                "host": host,
                "summary": None,
                "operation_id": None,
                "tags": [],
                "parameters": [],
                "request_body": None,
                "responses": [],
                "security": [],
                "deprecated": False,
                "source_type": "url",
                "source_url": source,
                "source_file": None,
                "evidence": "URL candidate from recon output; HTTP method and behavior not verified.",
            })
    return records


def extract_javascript_candidates(source_url, text, roots):
    records = []
    candidates = []
    candidates.extend((value.rstrip(");,]"), "absolute") for value in ABSOLUTE_URL.findall(text))
    candidates.extend((value, "route") for value in ROUTE_HINT.findall(text))
    for value, kind in candidates:
        url = urljoin(source_url, value)
        if not url_in_scope(url, roots):
            continue
        parsed = urlsplit(url)
        path = parsed.path or "/"
        records.append({
            "method": None,
            "path": path,
            "url": url,
            "host": parsed.hostname.lower() if parsed.hostname else "",
            "summary": None,
            "operation_id": None,
            "tags": [],
            "parameters": [],
            "request_body": None,
            "responses": [],
            "security": [],
            "deprecated": False,
            "source_type": "javascript",
            "source_url": source_url,
            "source_file": None,
            "evidence": "Route/URL string extracted from JavaScript; not verified.",
        })
    return records
