"""Conservative OpenAPI/Swagger specification discovery and fetching."""

import hashlib
import json
import os
import re
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import requests
except ImportError:
    requests = None

try:
    import yaml
except ImportError:
    yaml = None

from .scope import host_in_scope


COMMON_SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api-docs",
    "/api-docs/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-resources",
    "/.well-known/openapi.json",
)
SPEC_HINT = re.compile(r"(openapi|swagger|api[-_]?docs|postman).{0,80}\.(json|ya?ml)|/(openapi|swagger|api-docs)(/|$)", re.I)
ABSOLUTE_URL = re.compile(r"""https?://[^\s"'<>\\]+""", re.I)
RELATIVE_SPEC = re.compile(r"""(?:"|')([^"'<> ]{1,300}\.(?:json|ya?ml)(?:\?[^"'<> ]*)?)(?:"|')""", re.I)


def _safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")[:100] or "spec"


def _candidate_urls(targets, source_urls, source_texts, roots):
    candidates = []
    for host in targets:
        candidates.append("https://" + host + "/")
        for path in COMMON_SPEC_PATHS:
            candidates.append("https://" + host + path)
    for url in source_urls:
        if SPEC_HINT.search(url):
            candidates.append(url)
    for source_url, text in source_texts:
        for match in ABSOLUTE_URL.findall(text):
            candidate = match.rstrip(");,]")
            if SPEC_HINT.search(candidate) and _url_allowed(candidate, roots):
                candidates.append(candidate)
        for match in RELATIVE_SPEC.findall(text):
            if SPEC_HINT.search(match):
                candidate = urljoin(source_url, match)
                if _url_allowed(candidate, roots):
                    candidates.append(candidate)
    unique = []
    seen = set()
    for value in candidates:
        if not _url_allowed(value, roots):
            continue
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        normalized = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def _url_allowed(url, roots):
    try:
        parsed = urlsplit(url)
        return parsed.scheme in ("http", "https") and host_in_scope(parsed.hostname, roots)
    except ValueError:
        return False


def _read_bounded_response(response, limit):
    chunks = []
    size = 0
    for chunk in response.iter_content(chunk_size=16384):
        if not chunk:
            continue
        size += len(chunk)
        if size > limit:
            raise ValueError("response exceeded configured size limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_document(raw, content_type, url):
    text = raw.decode("utf-8-sig", errors="replace")
    parsed = urlsplit(url)
    looks_like_spec = (
        "openapi" in text[:5000].lower()
        or "swagger" in text[:5000].lower()
        or "paths" in text[:5000].lower()
        or "json" in (content_type or "").lower()
        or parsed.path.lower().endswith((".json", ".yaml", ".yml"))
    )
    if not looks_like_spec:
        return None, "not_spec_like"
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        if yaml is None:
            return None, "yaml_skipped_install_pyyaml"
        try:
            data = yaml.safe_load(text)
        except Exception:
            return None, "parse_error"
    if not isinstance(data, dict):
        return None, "not_object"
    if not (isinstance(data.get("paths"), dict) or data.get("swagger") or data.get("openapi")):
        return None, "missing_openapi_markers"
    return data, "parsed"


def discover_specs(targets, roots, source_urls, source_texts, output_dir, timeout=8, max_bytes=3145728):
    """Fetch only in-scope candidates; do not follow redirects or external $refs."""
    os.makedirs(os.path.join(output_dir, "specs"), exist_ok=True)
    if requests is None:
        return [], [], ["Python dependency missing: install requirements-api.txt (requests)."]

    candidates = _candidate_urls(targets, source_urls, source_texts, roots)
    records, parsed_specs, errors = [], [], []
    per_host_count = {}
    for url in candidates:
        host = urlsplit(url).hostname.lower()
        if per_host_count.get(host, 0) >= 30:
            continue
        per_host_count[host] = per_host_count.get(host, 0) + 1
        record = {"url": url, "host": host, "status": None, "content_type": None, "saved_as": None, "parse_status": "not_checked"}
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": "AutoRecon-API-Recon/0.1"},
            )
            record["status"] = response.status_code
            record["content_type"] = response.headers.get("Content-Type", "")
            if response.status_code != 200:
                record["parse_status"] = "http_status"
                response.close()
                records.append(record)
                time.sleep(0.1)
                continue
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                record["parse_status"] = "content_length_limit"
                response.close()
                records.append(record)
                continue
            raw = _read_bounded_response(response, max_bytes)
            response.close()
            data, parse_status = _parse_document(raw, record["content_type"], url)
            record["parse_status"] = parse_status
            if data is not None:
                digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
                filename = _safe_name(host + "_" + urlsplit(url).path.strip("/").replace("/", "_") + "_" + digest) + ".json"
                filepath = os.path.join(output_dir, "specs", filename)
                with open(filepath, "w", encoding="utf-8") as handle:
                    json.dump(data, handle, indent=2, ensure_ascii=False)
                record["saved_as"] = os.path.relpath(filepath, output_dir)
                parsed_specs.append({"url": url, "file": record["saved_as"], "document": data})
            records.append(record)
        except Exception as exc:
            record["parse_status"] = "request_error"
            record["error"] = str(exc)[:300]
            records.append(record)
            errors.append(url + ": " + str(exc)[:200])
        finally:
            time.sleep(0.1)
    return records, parsed_specs, errors
