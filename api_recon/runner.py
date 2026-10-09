"""API-only workflow coordinator for AutoRecon."""

import argparse
import csv
import json
import os
import re
import sys
import time
from urllib.parse import urljoin, urlsplit

try:
    import requests
except ImportError:
    requests = None

from .parser import extract_javascript_candidates, extract_url_candidates, parse_spec
from .scope import host_in_scope, read_host_file, url_in_scope
from .specs import discover_specs


MAX_JS_BYTES = 2 * 1024 * 1024
DEFAULT_OUTPUT = os.path.join("results", "api_recon")


def _write_text(path, lines):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(str(line).rstrip("\r\n") + "\n")


def _read_lines(path):
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return [line.strip() for line in handle if line.strip() and not line.lstrip().startswith("#")]


def _local_recon_inputs(roots, cwd="."):
    """Read existing recon outputs; do not invoke the general recon tools."""
    source_urls, js_urls, js_sources = [], [], []
    for current, dirs, files in os.walk(cwd):
        dirs[:] = [name for name in dirs if name not in {".git", ".venv", "venv", "node_modules", "__pycache__"}]
        if current.startswith(os.path.join(cwd, "results", "api_recon")):
            dirs[:] = []
            continue
        for filename in files:
            full_path = os.path.join(current, filename)
            if filename == "all_urls.txt":
                for url in _read_lines(full_path):
                    if url_in_scope(url, roots):
                        source_urls.append((url, full_path))
            elif filename == "js.txt":
                for url in _read_lines(full_path):
                    if url_in_scope(url, roots):
                        js_urls.append((url, full_path))
    # URL lists can also contain JS files; preserve unique paths and provenance.
    for url, source in source_urls:
        if urlsplit(url).path.lower().split("?", 1)[0].endswith(".js"):
            js_urls.append((url, source))
    seen = set()
    unique_js = []
    for url, source in js_urls:
        if url not in seen:
            seen.add(url)
            unique_js.append((url, source))
    if requests is not None:
        for url, source in unique_js:
            try:
                response = requests.get(
                    url, timeout=8, allow_redirects=False, stream=True,
                    headers={"User-Agent": "AutoRecon-API-Recon/0.1"},
                )
                if response.status_code != 200:
                    response.close()
                    continue
                declared = response.headers.get("Content-Length")
                if declared and declared.isdigit() and int(declared) > MAX_JS_BYTES:
                    response.close()
                    continue
                chunks, size = [], 0
                for chunk in response.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > MAX_JS_BYTES:
                        chunks = []
                        break
                    chunks.append(chunk)
                response.close()
                if chunks:
                    js_sources.append((url, b"".join(chunks).decode("utf-8", errors="replace"), source))
            except Exception:
                continue
            time.sleep(0.1)
    return sorted(set(url for url, _ in source_urls)), js_sources


def _load_spec_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _endpoint_key(record):
    return (record.get("method") or "?", record.get("host") or "", record.get("path") or "")


def _deduplicate(records):
    merged = {}
    for record in records:
        key = _endpoint_key(record)
        if key not in merged:
            merged[key] = record
            merged[key]["sources"] = [{
                "type": record.get("source_type"),
                "url": record.get("source_url"),
                "file": record.get("source_file"),
            }]
            continue
        current = merged[key]
        source = {
            "type": record.get("source_type"),
            "url": record.get("source_url"),
            "file": record.get("source_file"),
        }
        if source not in current["sources"]:
            current["sources"].append(source)
        # Keep richer specification metadata if it appears after a URL candidate.
        if record.get("source_type") == "openapi":
            current.update({k: v for k, v in record.items() if v not in (None, [], {})})
    return sorted(merged.values(), key=lambda item: (item.get("host") or "", item.get("path") or "", item.get("method") or ""))


def _safe_validation(endpoints, roots, timeout=6, max_requests=50):
    """Optional, low-volume GET-only reachability checks; never mutate resources."""
    results = []
    if requests is None:
        return [{"status": "skipped", "reason": "requests is not installed"}]
    count = 0
    seen = set()
    for endpoint in endpoints:
        url = endpoint.get("url")
        if not url or not url_in_scope(url, roots) or url in seen:
            continue
        # Only validate URLs with a known concrete host. Do not invent query values
        # for templated paths such as /users/{userId}.
        if "{" in url or "}" in url:
            continue
        seen.add(url)
        if count >= max_requests:
            break
        count += 1
        item = {"url": url, "method": "GET", "status_code": None, "content_type": None, "note": None}
        try:
            response = requests.get(
                url, timeout=timeout, allow_redirects=False, stream=True,
                headers={"User-Agent": "AutoRecon-API-Recon/0.1"},
            )
            item["status_code"] = response.status_code
            item["content_type"] = response.headers.get("Content-Type", "")
            item["note"] = "Reachability observation only; not a vulnerability verdict."
            response.close()
        except Exception as exc:
            item["note"] = "Request failed: " + str(exc)[:200]
        results.append(item)
        time.sleep(0.2)
    return results


def _write_csv(path, endpoints):
    fields = ["method", "host", "path", "url", "summary", "operation_id", "source_type", "source_url", "deprecated", "evidence"]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for endpoint in endpoints:
            row = dict(endpoint)
            row["host"] = row.get("host") or (urlsplit(row.get("source_url") or "").hostname or "")
            writer.writerow(row)


def _write_report(path, targets, spec_records, endpoints, validation):
    successful_specs = sum(1 for item in spec_records if item.get("parse_status") == "parsed")
    by_source = {}
    for endpoint in endpoints:
        by_source[endpoint.get("source_type", "unknown")] = by_source.get(endpoint.get("source_type", "unknown"), 0) + 1
    lines = [
        "# AutoRecon API Recon Report", "",
        "## Scope",
        "- Selected hosts: " + (", ".join(targets) if targets else "None"),
        "- Specification documents parsed: " + str(successful_specs),
        "- Deduplicated endpoint candidates: " + str(len(endpoints)),
        "- Optional validation observations: " + str(len(validation)),
        "",
        "## Endpoint sources",
    ]
    if by_source:
        lines.extend("- " + key + ": " + str(value) for key, value in sorted(by_source.items()))
    else:
        lines.append("- No endpoints were extracted.")
    lines += [
        "",
        "## Recommended manual review",
        "- Check object-level authorization on endpoints that accept object identifiers.",
        "- Check function-level authorization on privileged or administrative routes.",
        "- Review writable properties and sensitive response fields against the specification.",
        "- Review authentication, token refresh, file handling, webhooks, and business-critical flows.",
        "- Compare documented routes with JavaScript-derived and archived URL candidates.",
        "",
        "## Interpretation",
        "Discovered routes are candidates, not confirmed vulnerabilities. HTTP status codes and",
        "specification metadata do not establish authorization correctness. Validate findings",
        "manually with program-authorized test accounts and within the program's rules.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def run_api_recon(args):
    targets, invalid = read_host_file(args.domains_file)
    if not targets:
        print("[!] No valid target hosts found in: " + args.domains_file, file=sys.stderr)
        return 2

    if args.scope:
        roots, invalid_scope = read_host_file(args.scope)
        if not roots:
            print("[!] Scope file has no valid hostnames.", file=sys.stderr)
            return 2
    else:
        # In the absence of a broader explicit program scope, selected hosts are
        # the allowlist. Add --scope with the program's authorized root domains
        # when related API hosts are explicitly in scope.
        roots, invalid_scope = targets, []

    outside = [host for host in targets if not host_in_scope(host, roots)]
    if outside:
        print("[!] These targets are not covered by --scope: " + ", ".join(outside), file=sys.stderr)
        return 2

    output = os.path.abspath(args.output)
    os.makedirs(output, exist_ok=True)
    os.makedirs(os.path.join(output, "logs"), exist_ok=True)
    log_path = os.path.join(output, "logs", "api_recon.log")

    def log(message):
        print(message)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(message + "\n")

    _write_text(os.path.join(output, "api.domains.txt"), targets)
    _write_text(os.path.join(output, "invalid_inputs.txt"),
                ["domains.txt: line {line}: {value}".format(**item) for item in invalid] +
                ["scope: line {line}: {value}".format(**item) for item in invalid_scope])

    log("[+] API-only mode: general recon tools will not be rerun.")
    log("[+] Selected hosts: " + str(len(targets)))
    log("[+] Output directory: " + output)

    existing_urls, js_sources = _local_recon_inputs(roots)
    log("[+] Loaded in-scope URLs from existing recon outputs: " + str(len(existing_urls)))
    log("[+] JavaScript files read: " + str(len(js_sources)))

    spec_records, parsed_specs, spec_errors = discover_specs(
        targets=targets,
        roots=roots,
        source_urls=existing_urls,
        source_texts=[(url, text) for url, text, _source in js_sources],
        output_dir=output,
        timeout=args.timeout,
        max_bytes=args.max_spec_bytes,
    )
    with open(os.path.join(output, "discovered_specs.json"), "w", encoding="utf-8") as handle:
        json.dump(spec_records, handle, indent=2, ensure_ascii=False)
    _write_text(os.path.join(output, "spec_candidates.txt"), [item["url"] for item in spec_records])
    log("[+] Specification candidates checked: " + str(len(spec_records)))
    log("[+] Specifications parsed: " + str(len(parsed_specs)))

    endpoints = []
    for item in parsed_specs:
        endpoints.extend(parse_spec(item["document"], item["url"], item["file"]))
    url_pairs = [(url, "existing recon URL inventory") for url in existing_urls]
    endpoints.extend(extract_url_candidates(url_pairs, roots))
    for js_url, text, source in js_sources:
        for record in extract_javascript_candidates(js_url, text, roots):
            record["source_file"] = source
            endpoints.append(record)

    endpoints = _deduplicate(endpoints)
    # Preserve only in-scope concrete URLs and endpoint hosts.
    endpoints = [item for item in endpoints if
                 (not item.get("url") or url_in_scope(item["url"], roots)) and
                 (not item.get("host") or host_in_scope(item["host"], roots))]

    with open(os.path.join(output, "api_endpoints.json"), "w", encoding="utf-8") as handle:
        json.dump(endpoints, handle, indent=2, ensure_ascii=False)
    _write_text(
        os.path.join(output, "api_endpoints.txt"),
        ["{method:7} {host}{path}  [{source}]".format(
            method=item.get("method") or "CANDIDATE",
            host=(item.get("host") or ""),
            path=item.get("path") or "/",
            source=item.get("source_type") or "unknown",
        ) for item in endpoints],
    )
    _write_csv(os.path.join(output, "api_endpoints.csv"), endpoints)
    _write_text(os.path.join(output, "discovered_urls.txt"), existing_urls)
    _write_text(os.path.join(output, "javascript", "js_urls.txt"), [url for url, _text, _source in js_sources])
    _write_text(os.path.join(output, "javascript", "extracted_endpoints.txt"),
                [item.get("url") or item.get("path") or "" for item in endpoints if item.get("source_type") == "javascript"])

    validation = _safe_validation(endpoints, roots) if args.validate else []
    if args.validate:
        with open(os.path.join(output, "validation_results.json"), "w", encoding="utf-8") as handle:
            json.dump(validation, handle, indent=2, ensure_ascii=False)

    _write_report(os.path.join(output, "report.md"), targets, spec_records, endpoints, validation)
    if spec_errors:
        _write_text(os.path.join(output, "logs", "spec_errors.txt"), spec_errors)
    log("[+] Endpoint candidates: " + str(len(endpoints)))
    log("[+] Finished. Review report.md and api_endpoints.json.")
    return 0


def build_api_parser():
    parser = argparse.ArgumentParser(
        prog="autorecon --api",
        description="Run API-only reconnaissance on selected, authorized API hosts.",
    )
    parser.add_argument("--api", dest="domains_file", required=True, help="Text file containing selected API hostnames.")
    parser.add_argument("--scope", help="Optional file of explicitly authorized root domains; defaults to selected hosts.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output directory (default: results/api_recon).")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds (default: 8).")
    parser.add_argument("--max-spec-bytes", type=int, default=3145728, help="Maximum response size for a spec (default: 3 MiB).")
    parser.add_argument("--validate", action="store_true", help="Enable low-volume, non-mutating GET reachability checks.")
    return parser


def main_api(argv=None):
    parser = build_api_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.max_spec_bytes <= 0:
        parser.error("--timeout and --max-spec-bytes must be positive")
    return run_api_recon(args)
