from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}

_READ_ONLY_EXACT: set[tuple[str, str]] = {
    ("GET", "/health"),
    ("GET", "/auth/me"),
    ("GET", "/public-review/config"),
    ("GET", "/questions/ui"),
    ("GET", "/questions/recent"),
    ("POST", "/questions/ask"),
    ("POST", "/questions/speech"),
    ("GET", "/observed-destinations/ui"),
    ("GET", "/observed-destinations/summary"),
    ("GET", "/observed-destinations/top"),
    ("GET", "/observed-destinations/asns"),
    ("GET", "/observed-destinations/categories"),
    ("GET", "/observed-destinations/trends-summary"),
    ("GET", "/observed-destinations/trends"),
    ("GET", "/observed-destinations/trends/asns"),
    ("GET", "/observed-destinations/trends/categories"),
    ("GET", "/bgp/top/peers"),
    ("GET", "/bgp/top/changes"),
    ("GET", "/bgp/top/prefixes"),
    ("GET", "/bgp/top/origin-asns"),
    ("GET", "/inventory/sites"),
    ("GET", "/inventory/hosts"),
    ("GET", "/inventory/search"),
    ("GET", "/inventory/peer-links"),
    ("GET", "/inventory/peers/unmatched"),
    ("GET", "/inventory/peers/matched"),
    ("GET", "/inventory/ui"),
    ("GET", "/inventory/discovery/runs"),
    ("GET", "/inventory/discovery/candidates"),
    ("GET", "/ixbr/locations"),
    ("GET", "/learning/requests"),
    ("GET", "/learning/known-networks"),
    ("GET", "/learning/search"),
    ("GET", "/semantic/search"),
    ("GET", "/semantic/metrics"),
    ("GET", "/semantic/health"),
    ("GET", "/semantic/documents"),
    ("GET", "/search/prefix"),
    ("GET", "/measurements/ping/latest"),
    ("GET", "/measurements/ping/summary"),
    ("GET", "/peers/ping"),
    ("GET", "/peers/ping/missing"),
    ("GET", "/measurements/traceroute/latest"),
    ("GET", "/measurements/traceroute/summary"),
    ("GET", "/measurements/traceroute/hop-summary"),
    ("GET", "/measurements/traceroute/classification-summary"),
    ("GET", "/measurements/traceroute/unmatched-private-hops"),
    ("GET", "/measurements/traceroute/classified-hops"),
    ("GET", "/measurements/traceroute/matched-hops"),
    ("GET", "/measurements/traceroute/private-hops"),
    ("GET", "/synthetic/runs/latest"),
    ("GET", "/synthetic/domain"),
    ("GET", "/synthetic/ip-results"),
    ("GET", "/route-learning/sessions/demo/cloudflare/post-change-run-plan"),
}

_READ_ONLY_REGEX = (
    re.compile(r"^/questions/[^/]+$"),
    re.compile(r"^/questions/[^/]+/action-plan$"),
    re.compile(r"^/questions/[^/]+/full$"),
    re.compile(r"^/questions/[^/]+/traceroute-graph$"),
    re.compile(r"^/questions/[^/]+/speech$"),
    re.compile(r"^/observed-destinations/baselines$"),
    re.compile(r"^/bgp/visibility/ip/[^/]+$"),
    re.compile(r"^/inventory/sites/[^/]+$"),
    re.compile(r"^/inventory/sites/[^/]+/hosts$"),
    re.compile(r"^/inventory/sites/[^/]+/public-context$"),
    re.compile(r"^/inventory/hosts/[^/]+$"),
    re.compile(r"^/inventory/discovery/candidates/[^/]+$"),
    re.compile(r"^/ixbr/locations/[^/]+/participants$"),
    re.compile(r"^/ixbr/locations/[^/]+/bgp-summary$"),
    re.compile(r"^/ixbr/locations/[^/]+/participants/seen-as-origin$"),
    re.compile(r"^/ixbr/locations/[^/]+/participants/not-seen-as-origin$"),
    re.compile(r"^/ixbr/locations/[^/]+/participants/[^/]+$"),
    re.compile(r"^/learning/requests/[^/]+$"),
    re.compile(r"^/learning/requests/[^/]+/answer$"),
    re.compile(r"^/learning/requests/[^/]+/classifications$"),
    re.compile(r"^/learning/memory/domain/.+$"),
    re.compile(r"^/learning/memory/entity$"),
    re.compile(r"^/learning/classifications/entity$"),
    re.compile(r"^/semantic/documents/[^/]+$"),
    re.compile(r"^/measurements/ping/history/.+$"),
    re.compile(r"^/measurements/traceroute/history/.+$"),
    re.compile(r"^/measurements/traceroute/hops/[^/]+$"),
    re.compile(r"^/measurements/traceroute/latest-hops/.+$"),
    re.compile(r"^/measurements/traceroute/latest-hops-enriched/.+$"),
    re.compile(r"^/measurements/traceroute/latest-hops-classified/.+$"),
    re.compile(r"^/synthetic/runs/[^/]+$"),
    re.compile(r"^/synthetic/hosts/[^/]+$"),
    re.compile(r"^/route-graph/runs/[^/]+$"),
)


def _is_read_only_external_routes_path(method: str, path: str) -> bool:
    if method.upper() != "GET":
        return False
    normalized = path.rstrip("/") or "/"
    if normalized in {
        "/external-routes/services",
        "/external-routes/hops",
        "/external-routes/unknown-hops",
        "/external-routes/compare",
        "/external-routes/ui",
    }:
        return True
    if re.fullmatch(r"^/external-routes/services/[^/]+/summary$", normalized):
        return True
    if re.fullmatch(r"^/external-routes/services/[^/]+/hops$", normalized):
        return True
    if re.fullmatch(r"^/external-routes/services/[^/]+/edges$", normalized):
        return True
    if re.fullmatch(r"^/external-routes/services/[^/]+/trace-runs/[^/]+/graph$", normalized):
        return True
    if re.fullmatch(r"^/external-routes/hops/.+$", normalized):
        return True
    if re.fullmatch(r"^/external-routes/hops/.+/context$", normalized):
        return True
    return False


@dataclass(frozen=True)
class AuthUser:
    username: str
    role: str


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUE_VALUES


def auth_enabled() -> bool:
    return _env_bool("ROUTEBRAIN_AUTH_ENABLED", False)


def _auth_value(name: str) -> str:
    return os.getenv(name, "").strip()


def _basic_auth_credentials(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError, binascii.Error):
        return None
    username, separator, password = decoded.partition(":")
    if separator != ":":
        return None
    return username, password


def _match_exact(method: str, path: str, candidates: Iterable[tuple[str, str]]) -> bool:
    normalized_method = method.upper()
    normalized_path = path.rstrip("/") or "/"
    return any(normalized_method == candidate_method and normalized_path == candidate_path for candidate_method, candidate_path in candidates)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_read_only_observed_destinations_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    if not normalized.startswith("/observed-destinations/"):
        return False
    parts = normalized.split("/")
    if len(parts) < 3:
        return False
    section = parts[1]
    head = parts[2]
    tail = parts[3:]
    if section != "observed-destinations":
        return False
    if head == "baselines":
        if len(tail) == 0:
            return True
        if len(tail) >= 1 and _is_ip(tail[0]):
            if len(tail) == 1:
                return True
            return tail[1] in {"measurements", "traceroute-graph"}
        return False
    if not _is_ip(head):
        return False
    if len(tail) == 0:
        return True
    return tail in (["report"], ["trend"])


def is_admin(user: AuthUser | None) -> bool:
    return bool(user and user.role == "admin")


def is_viewer(user: AuthUser | None) -> bool:
    return bool(user and user.role == "viewer")


def _authenticate(request: Request) -> AuthUser | None:
    if not auth_enabled():
        return None
    credentials = _basic_auth_credentials(request)
    if credentials is None:
        return None
    supplied_username, supplied_password = credentials
    admin_username = _auth_value("ROUTEBRAIN_AUTH_ADMIN_USERNAME")
    admin_password = _auth_value("ROUTEBRAIN_AUTH_ADMIN_PASSWORD")
    viewer_username = _auth_value("ROUTEBRAIN_AUTH_VIEWER_USERNAME")
    viewer_password = _auth_value("ROUTEBRAIN_AUTH_VIEWER_PASSWORD")
    if admin_username and admin_password and secrets.compare_digest(supplied_username, admin_username) and secrets.compare_digest(supplied_password, admin_password):
        return AuthUser(username=admin_username, role="admin")
    if viewer_username and viewer_password and secrets.compare_digest(supplied_username, viewer_username) and secrets.compare_digest(supplied_password, viewer_password):
        return AuthUser(username=viewer_username, role="viewer")
    return None


def get_current_user(request: Request) -> AuthUser | None:
    user = getattr(request.state, "user", None)
    if isinstance(user, AuthUser):
        return user
    return None


def _permissions_for_role(role: str) -> list[str]:
    base = [
        "read:ui",
        "read:health",
        "read:questions",
        "read:observed_destinations",
        "read:bgp_visibility",
        "read:inventory",
    ]
    if role == "admin":
        return [
            *base,
            "write:collect",
            "write:enrich",
            "write:promote_baseline",
            "write:measure_baseline",
            "write:question_actions",
            "write:learning",
            "write:semantic",
            "read:inventory",
        ]
    return base


def required_auth_response() -> JSONResponse:
    return JSONResponse(
        {"detail": "Autenticação obrigatória."},
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="RouteBrain"'},
    )


def forbidden_role_response() -> JSONResponse:
    return JSONResponse({"detail": "Ação exige permissão de operador/admin."}, status_code=403)


def is_auth_protected_path(method: str, path: str) -> bool:
    normalized_path = path.rstrip("/") or "/"
    if normalized_path.startswith("/static/"):
        return False
    if _is_read_only_external_routes_path(method, normalized_path):
        return False
    if _match_exact(method, normalized_path, _READ_ONLY_EXACT):
        return False
    if any(pattern.fullmatch(normalized_path) for pattern in _READ_ONLY_REGEX):
        return False
    if _is_read_only_observed_destinations_path(normalized_path):
        return False
    if normalized_path in {"/docs", "/redoc", "/openapi.json"}:
        return True
    return True


def is_viewer_allowed(method: str, path: str) -> bool:
    normalized_path = path.rstrip("/") or "/"
    if normalized_path.startswith("/static/"):
        return True
    if normalized_path in {"/docs", "/redoc", "/openapi.json"}:
        return False
    if method.upper() == "GET" and normalized_path in {
        "/",
        "/route-graph/global",
        "/route-graph/ui",
        "/route-graph/workspace",
        "/route-memory/graph-viewer",
        "/route-memory/graphs/latest",
        "/route-memory/grafana/latest",
        "/route-memory/grafana/latest/summary",
        "/route-memory/grafana/latest/nodes",
        "/route-memory/grafana/latest/edges",
        "/route-memory/grafana/latest/divergences",
        "/route-learning/demo/ui",
        "/route-graph/clusters",
        "/route-graph/unknown",
        "/route-graph/private-path",
    }:
        return True
    if method.upper() == "GET" and re.fullmatch(r"^/route-memory/graphs/[^/]+$", normalized_path):
        return True
    if method.upper() == "GET" and re.fullmatch(r"^/route-memory/grafana/graphs/[^/]+(?:/(summary|nodes|edges|divergences))?$", normalized_path):
        return True
    if method.upper() == "GET" and re.fullmatch(r"^/route-graph/service/[^/]+$", normalized_path):
        return True
    if method.upper() == "GET" and re.fullmatch(r"^/route-graph/hop/.+$", normalized_path):
        return True
    if method.upper() == "GET" and normalized_path == "/route-graph/compare":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/demo/8.8.8.8/visual":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/8.8.8.8/visual":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/visual":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/dedicated-run-plan":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/post-change-run-plan":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/learning-comparison-plan":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/route-profile":
        return True
    if method.upper() == "GET" and normalized_path == "/route-learning/sessions/demo/cloudflare/temporal-comparison":
        return True
    if _is_read_only_external_routes_path(method, normalized_path):
        return True
    if _match_exact(method, normalized_path, _READ_ONLY_EXACT):
        return True
    if any(pattern.fullmatch(normalized_path) for pattern in _READ_ONLY_REGEX):
        return True
    if _is_read_only_observed_destinations_path(normalized_path):
        return True
    return False


def auth_payload_for_request(request: Request) -> dict[str, Any]:
    user = get_current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Não autenticado.")
    return {
        "authenticated": True,
        "username": user.username,
        "role": user.role,
        "permissions": _permissions_for_role(user.role),
    }


async def auth_middleware(request: Request, call_next):
    if not auth_enabled():
        request.state.user = None
        return await call_next(request)

    user = _authenticate(request)
    request.state.user = user
    if user is None and is_auth_protected_path(request.method, request.url.path):
        return required_auth_response()
    if user is not None and user.role == "viewer" and not is_viewer_allowed(request.method, request.url.path):
        return forbidden_role_response()
    if user is None and request.url.path in {"/health", "/auth/me"}:
        return required_auth_response()
    return await call_next(request)
