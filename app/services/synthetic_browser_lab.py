from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "synthetic_browser_lab"
HAR_DIR = OUTPUT_DIR / "har"

SENSITIVE_HEADERS = {
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
}


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL deve começar com http:// ou https:// e conter host válido.")
    return url


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value)


def _filter_headers(headers: dict[str, str] | list[dict[str, str]] | None) -> dict[str, str]:
    if not headers:
        return {}
    if isinstance(headers, list):
        items = ((item.get("name", ""), item.get("value", "")) for item in headers)
    else:
        items = headers.items()
    filtered: dict[str, str] = {}
    for key, value in items:
        if key.lower() in SENSITIVE_HEADERS:
            continue
        filtered[key] = value
    return filtered


def _parse_request_url(request_url: str) -> dict[str, Any]:
    parsed = urlparse(request_url)
    return {
        "scheme": parsed.scheme or None,
        "hostname": parsed.hostname or None,
        "port": parsed.port,
        "path": parsed.path or "/",
        "query_present": bool(parsed.query),
    }


def _status_bucket(status: int | None) -> str:
    if status is None:
        return "failed"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    if 500 <= status < 600:
        return "5xx"
    return "failed"


def _request_failure_text(request: Any) -> str:
    failure_attr = getattr(request, "failure", None)
    if callable(failure_attr):
        try:
            value = failure_attr()
            return str(value) if value else "request failed"
        except Exception:
            return "request failed"
    if failure_attr:
        return str(failure_attr)
    return "request failed"


def _scrub_har_file(har_path: Path) -> None:
    try:
        data = json.loads(har_path.read_text())
    except Exception:
        return

    for entry in data.get("log", {}).get("entries", []):
        request = entry.get("request", {})
        response = entry.get("response", {})
        request["headers"] = [
            header
            for header in request.get("headers", [])
            if header.get("name", "").lower() not in SENSITIVE_HEADERS
        ]
        response["headers"] = [
            header
            for header in response.get("headers", [])
            if header.get("name", "").lower() not in SENSITIVE_HEADERS
        ]
        for cookie_section in ("cookies",):
            if cookie_section in request:
                request[cookie_section] = []
            if cookie_section in response:
                response[cookie_section] = []

    har_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def run_synthetic_navigation(
    url: str,
    wait_until: str = "networkidle",
    timeout_ms: int = 30000,
    headless: bool = True,
    save_har: bool = True,
    label: str | None = None,
) -> dict[str, Any]:
    normalized_url = validate_url(url)
    parsed = urlparse(normalized_url)
    safe_host = _safe_name(parsed.hostname or "unknown")
    started_at = datetime.now(timezone.utc)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if save_har:
        HAR_DIR.mkdir(parents=True, exist_ok=True)

    request_store: dict[str, dict[str, Any]] = {}
    request_order: list[str] = []
    page_status: int | None = None
    final_url = normalized_url
    title = ""
    error_text = ""

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context_kwargs: dict[str, Any] = {}
        har_path: Path | None = None
        if save_har:
            timestamp = started_at.strftime("%Y%m%dT%H%M%S%fZ")
            har_path = HAR_DIR / f"synthetic_browser_{safe_host}_{timestamp}.har"
            context_kwargs["record_har_path"] = str(har_path)
            context_kwargs["record_har_content"] = "omit"

        context = browser.new_context(**context_kwargs)
        page = context.new_page()

        def _upsert_request(request: Any, *, response: Any | None = None, failure: str | None = None) -> None:
            key = str(id(request))
            record = request_store.get(key)
            if record is None:
                parsed_request = _parse_request_url(request.url)
                record = {
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "status": None,
                    "status_text": None,
                    "request_headers": _filter_headers(getattr(request, "headers", {})),
                    "response_headers": {},
                    "failure": None,
                    "timing": None,
                    **parsed_request,
                }
                request_store[key] = record
                request_order.append(key)

            if response is not None:
                record["status"] = response.status
                record["status_text"] = response.status_text
                record["response_headers"] = _filter_headers(getattr(response, "headers", {}))
                try:
                    record["timing"] = response.request.timing
                except Exception:
                    record["timing"] = None
            if failure:
                record["failure"] = failure

        page.on("request", lambda request: _upsert_request(request))
        page.on("response", lambda response: _upsert_request(response.request, response=response))
        page.on("requestfailed", lambda request: _upsert_request(request, failure=_request_failure_text(request)))

        try:
            response = page.goto(normalized_url, wait_until=wait_until, timeout=timeout_ms)
            if response is not None:
                page_status = response.status
                _upsert_request(response.request, response=response)
            try:
                title = page.title()
            except Exception:
                title = ""
            final_url = page.url
        except Exception as exc:
            error_text = str(exc)
            try:
                title = page.title()
            except Exception:
                title = ""
            final_url = page.url or normalized_url
        finally:
            context.close()
            browser.close()

    finished_at = datetime.now(timezone.utc)
    requests = [request_store[key] for key in request_order]
    summary_counter = Counter(_status_bucket(item.get("status")) for item in requests)
    resource_types = Counter(item.get("resource_type") or "unknown" for item in requests)
    hosts = sorted({item.get("hostname") for item in requests if item.get("hostname")})

    summary = {
        "total_requests": len(requests),
        "total_hosts": len(hosts),
        "hosts": hosts,
        "status_summary": {
            "2xx": summary_counter.get("2xx", 0),
            "3xx": summary_counter.get("3xx", 0),
            "4xx": summary_counter.get("4xx", 0),
            "5xx": summary_counter.get("5xx", 0),
            "failed": summary_counter.get("failed", 0),
        },
        "resource_types": dict(resource_types),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed_seconds": round((finished_at - started_at).total_seconds(), 3),
        "page_status": page_status,
        "error": error_text or None,
    }

    timestamp = started_at.strftime("%Y%m%dT%H%M%S%fZ")
    json_path = OUTPUT_DIR / f"synthetic_browser_{safe_host}_{timestamp}.json"
    payload = {
        "url": normalized_url,
        "final_url": final_url,
        "title": title,
        "label": label,
        "json_path": str(json_path),
        "har_path": str(har_path) if save_har and har_path else None,
        "summary": summary,
        "requests": requests,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    if save_har and har_path:
        _scrub_har_file(har_path)

    return payload
