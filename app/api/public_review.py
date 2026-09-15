from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from starlette.responses import JSONResponse, Response

from app.api.auth import auth_enabled

PUBLIC_REVIEW_BLOCKED_MESSAGE = "Ação exige perfil operador/admin."
PUBLIC_REVIEW_BANNER_MESSAGE = (
    "RBAC ativo: viewer é somente leitura; ações operacionais exigem perfil operador/admin."
)

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_DEFAULT_METHODS = {"GET", "HEAD", "POST"}


@dataclass(frozen=True)
class PublicRouteRule:
    methods: frozenset[str]
    kind: str
    value: str

    def matches(self, method: str, path: str) -> bool:
        if method not in self.methods:
            return False
        if self.kind == "exact":
            return path == self.value
        if self.kind == "prefix":
            return path.startswith(self.value)
        if self.kind == "regex":
            return bool(re.fullmatch(self.value, path))
        return False


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE_VALUES


def is_public_review_mode() -> bool:
    if auth_enabled():
        return False
    return _env_bool("ROUTEBRAIN_PUBLIC_REVIEW_MODE", False)


def public_review_require_auth() -> bool:
    return _env_bool("ROUTEBRAIN_PUBLIC_REVIEW_REQUIRE_AUTH", True)


def public_review_block_active_actions() -> bool:
    return _env_bool("ROUTEBRAIN_PUBLIC_REVIEW_BLOCK_ACTIVE_ACTIONS", True)


def _method_set(*methods: str) -> frozenset[str]:
    expanded = {method.upper() for method in methods}
    if "GET" in expanded:
        expanded.add("HEAD")
    return frozenset(expanded)


def _default_allowed_rules() -> list[PublicRouteRule]:
    return [
        PublicRouteRule(_method_set("GET"), "exact", "/health"),
        PublicRouteRule(_method_set("GET"), "exact", "/public-review/config"),
        PublicRouteRule(_method_set("GET"), "exact", "/questions/ui"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/ui"),
        PublicRouteRule(_method_set("GET"), "regex", r"/route-graph/runs/[^/]+"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/graph-viewer"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/graphs/latest"),
        PublicRouteRule(_method_set("GET"), "regex", r"/route-memory/graphs/[^/]+"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/grafana/latest"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/grafana/latest/summary"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/grafana/latest/nodes"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/grafana/latest/edges"),
        PublicRouteRule(_method_set("GET"), "exact", "/route-memory/grafana/latest/divergences"),
        PublicRouteRule(_method_set("GET"), "regex", r"/route-memory/grafana/graphs/[^/]+(?:/(summary|nodes|edges|divergences))?"),
        PublicRouteRule(_method_set("GET"), "prefix", "/static/"),
        PublicRouteRule(_method_set("GET"), "exact", "/questions/recent"),
        PublicRouteRule(_method_set("POST"), "exact", "/questions/ask"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/summary"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/top"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/asns"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/categories"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/trends-summary"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/trends"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/trends/asns"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/trends/categories"),
        PublicRouteRule(_method_set("GET"), "exact", "/observed-destinations/baselines"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/baselines/[^/]+"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/baselines/[^/]+/measurements"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/baselines/[^/]+/traceroute-graph"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/[^/]+"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/[^/]+/report"),
        PublicRouteRule(_method_set("GET"), "regex", r"/observed-destinations/[^/]+/trend"),
        PublicRouteRule(_method_set("GET"), "regex", r"/bgp/visibility/ip/[^/]+"),
    ]


def _parse_extra_allowed_rule(raw_rule: str) -> PublicRouteRule | None:
    text = raw_rule.strip()
    if not text:
        return None

    method = "GET"
    path = text
    parts = text.split(None, 1)
    if len(parts) == 2 and parts[0].upper() in _DEFAULT_METHODS:
        method = parts[0].upper()
        path = parts[1].strip()

    if not path.startswith("/"):
        return None
    if path.endswith("*"):
        return PublicRouteRule(_method_set(method), "prefix", path[:-1])
    return PublicRouteRule(_method_set(method), "exact", path)


def _extra_allowed_rules() -> list[PublicRouteRule]:
    raw = os.getenv("ROUTEBRAIN_PUBLIC_REVIEW_ALLOWED_PATHS", "")
    rules: list[PublicRouteRule] = []
    for item in raw.split(","):
        rule = _parse_extra_allowed_rule(item)
        if rule is not None:
            rules.append(rule)
    return rules


def public_review_allowed_rules() -> list[PublicRouteRule]:
    return [*_default_allowed_rules(), *_extra_allowed_rules()]


def public_review_allowed_paths_for_report() -> list[str]:
    rows: list[str] = []
    for rule in public_review_allowed_rules():
        methods = "/".join(sorted(rule.methods - {"HEAD"} or rule.methods))
        prefix = "REGEX" if rule.kind == "regex" else "PREFIX" if rule.kind == "prefix" else "EXACT"
        rows.append(f"{methods} {prefix} {rule.value}")
    return rows


def public_review_blocked_paths_for_report() -> list[str]:
    return [
        "POST /observed-destinations/collect",
        "POST /observed-destinations/enrich",
        "POST /observed-destinations/{ip}/promote",
        "POST /observed-destinations/baselines/{ip}/measure",
        "POST /observed-destinations/baselines/{ip}/snapshot",
        "POST /questions/{uid}/approve-active",
        "POST /questions/{uid}/execute-active",
        "POST /questions/{uid}/actions/*",
        "POST/PUT/PATCH/DELETE demais rotas fora da allowlist pública",
        "GET /docs",
        "GET /redoc",
        "GET /openapi.json",
        "Rotas /learning, /semantic, /synthetic, /inventory e medições fora da allowlist",
    ]


def is_public_route_allowed(method: str, path: str) -> bool:
    normalized_method = method.upper()
    normalized_path = path.rstrip("/") or "/"
    return any(rule.matches(normalized_method, normalized_path) for rule in public_review_allowed_rules())


_SENSITIVE_RULES = [
    PublicRouteRule(_method_set("POST"), "exact", "/observed-destinations/collect"),
    PublicRouteRule(_method_set("POST"), "exact", "/observed-destinations/enrich"),
    PublicRouteRule(_method_set("POST"), "regex", r"/observed-destinations/[^/]+/promote"),
    PublicRouteRule(_method_set("POST"), "regex", r"/observed-destinations/baselines/[^/]+/measure"),
    PublicRouteRule(_method_set("POST"), "regex", r"/observed-destinations/baselines/[^/]+/snapshot"),
    PublicRouteRule(_method_set("POST"), "regex", r"/questions/[^/]+/approve-active"),
    PublicRouteRule(_method_set("POST"), "regex", r"/questions/[^/]+/execute-active"),
    PublicRouteRule(_method_set("POST"), "regex", r"/questions/[^/]+/actions/[^/]+"),
]


def is_public_action_blocked(method: str, path: str) -> bool:
    if not public_review_block_active_actions():
        return False
    normalized_method = method.upper()
    normalized_path = path.rstrip("/") or "/"
    return any(rule.matches(normalized_method, normalized_path) for rule in _SENSITIVE_RULES)


def _unauthorized_response() -> JSONResponse:
    return JSONResponse(
        {"detail": "Autenticação obrigatória para acessar o modo de revisão pública."},
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="RouteBrain Public Review"'},
    )


def _auth_not_configured_response() -> JSONResponse:
    return JSONResponse(
        {"detail": "Autenticação de revisão pública não configurada no servidor."},
        status_code=503,
    )


def _forbidden_response() -> JSONResponse:
    return JSONResponse({"detail": PUBLIC_REVIEW_BLOCKED_MESSAGE}, status_code=403)


def _basic_auth_ok(request: Request) -> bool:
    username = os.getenv("ROUTEBRAIN_PUBLIC_REVIEW_USERNAME", "")
    password = os.getenv("ROUTEBRAIN_PUBLIC_REVIEW_PASSWORD", "")
    if not username or not password:
        return False

    header = request.headers.get("authorization", "")
    prefix = "Basic "
    if not header.startswith(prefix):
        return False
    try:
        decoded = base64.b64decode(header[len(prefix) :], validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError, binascii.Error):
        return False
    supplied_username, separator, supplied_password = decoded.partition(":")
    if separator != ":":
        return False
    return bool(
        secrets.compare_digest(supplied_username, username)
        and secrets.compare_digest(supplied_password, password)
    )


async def public_review_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if auth_enabled():
        return await call_next(request)
    if not is_public_review_mode():
        return await call_next(request)

    user = getattr(request.state, "user", None)
    if getattr(user, "role", None) == "admin":
        return await call_next(request)

    path = request.url.path
    method = request.method.upper()

    if public_review_require_auth():
        if not os.getenv("ROUTEBRAIN_PUBLIC_REVIEW_USERNAME") or not os.getenv("ROUTEBRAIN_PUBLIC_REVIEW_PASSWORD"):
            return _auth_not_configured_response()
        if not _basic_auth_ok(request):
            return _unauthorized_response()

    if is_public_action_blocked(method, path):
        return _forbidden_response()

    if not is_public_route_allowed(method, path):
        return _forbidden_response()

    return await call_next(request)


_PUBLIC_DROP_KEYS = {
    "audio_source_url",
    "command",
    "debug_context",
    "links",
    "metadata",
    "payload",
    "query",
    "query_string",
    "raw_context",
    "raw_line",
    "raw_payload",
    "source-address",
    "source_address",
    "source_label",
    "src-address",
    "src_address",
    "url",
    "full_url",
    "hops",
    "raw_output",
    "rtt_ms_values",
}


def _mask_private_address(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    if any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
            getattr(address, "is_site_local", False),
        )
    ):
        return "private-hop-redacted"
    return value


def sanitize_public_payload(value: Any) -> Any:
    if isinstance(value, list):
        return [sanitize_public_payload(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_public_payload(item) for item in value]
    if not isinstance(value, dict):
        return value

    clean: dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key).lower()
        if key_text in _PUBLIC_DROP_KEYS:
            continue
        if any(token in key_text for token in ("src-address", "source-address", "payload", "query_string")):
            continue
        if key_text in {"hop_ip", "ip", "target", "target_ip"}:
            clean[key] = _mask_private_address(item)
            continue
        clean[key] = sanitize_public_payload(item)
    return clean


def public_review_client_config() -> dict[str, Any]:
    return {
        "public_review_mode": is_public_review_mode(),
        "auth_required": public_review_require_auth(),
        "active_actions_blocked": public_review_block_active_actions(),
        "domain": os.getenv("ROUTEBRAIN_PUBLIC_DOMAIN", ""),
        "message": PUBLIC_REVIEW_BANNER_MESSAGE,
    }
