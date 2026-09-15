from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

try:
    import yaml
except Exception as exc:  # pragma: no cover - dependency issue
    yaml = None  # type: ignore[assignment]
    _YAML_IMPORT_ERROR = exc
else:
    _YAML_IMPORT_ERROR = None

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "synthetic_targets.yml"
LOCAL_POLICY_PATH = PROJECT_ROOT / "config" / "synthetic_targets.local.yml"
DEFAULT_BLOCKED_DOMAINS = ["localhost", "127.0.0.1", "0.0.0.0"]
DEFAULT_BLOCKED_SUFFIXES = [".local", ".internal", ".lan", ".home", ".corp"]
DEFAULT_BLOCKED_NETWORKS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def _safe_list(values: Any) -> list[str]:
    if not values:
        return []
    if not isinstance(values, list):
        values = [values]
    items = []
    for value in values:
        if value is None:
            continue
        item = str(value).strip().lower()
        if item:
            items.append(item)
    return items


def _resolve_policy_selection(cli_policy_path: str | Path | None = None) -> tuple[Path | None, str]:
    if cli_policy_path is not None:
        return Path(cli_policy_path), "cli"

    env_policy = os.getenv("ROUTEBRAIN_SYNTHETIC_POLICY")
    if env_policy:
        return Path(env_policy), "env"

    if LOCAL_POLICY_PATH.exists():
        return LOCAL_POLICY_PATH, "local"

    if DEFAULT_POLICY_PATH.exists():
        return DEFAULT_POLICY_PATH, "default"

    return None, "fallback"


def resolve_synthetic_policy_path(cli_policy_path: str | Path | None = None) -> Path | None:
    return _resolve_policy_selection(cli_policy_path)[0]


def _build_policy_from_data(path: Path | None, source: str, data: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "allowed_domains": _safe_list((data or {}).get("allowed_domains")),
        "blocked_domains": _safe_list((data or {}).get("blocked_domains")) or list(DEFAULT_BLOCKED_DOMAINS),
        "blocked_suffixes": _safe_list((data or {}).get("blocked_suffixes")) or list(DEFAULT_BLOCKED_SUFFIXES),
        "blocked_networks": _safe_list((data or {}).get("blocked_networks")) or list(DEFAULT_BLOCKED_NETWORKS),
        "notes": [str(item) for item in ((data or {}).get("notes") or []) if item is not None],
        "policy_path": str(path) if path else None,
        "policy_source": source,
    }


def load_synthetic_target_policy(
    config_path: str | Path | None = None,
    source_hint: str | None = None,
) -> dict[str, Any]:
    path, resolved_source = _resolve_policy_selection(config_path)
    source = source_hint or resolved_source
    default_policy = {
        "allowed_domains": [],
        "blocked_domains": list(DEFAULT_BLOCKED_DOMAINS),
        "blocked_suffixes": list(DEFAULT_BLOCKED_SUFFIXES),
        "blocked_networks": list(DEFAULT_BLOCKED_NETWORKS),
        "notes": [],
        "policy_path": str(path) if path else None,
        "policy_source": source,
    }

    if path is None:
        return default_policy
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de política sintética não encontrado: {path}")
    if yaml is None:  # pragma: no cover - dependency issue
        raise RuntimeError(f"PyYAML não está disponível: {_YAML_IMPORT_ERROR}")

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:  # pragma: no cover - ambiente externo
        raise RuntimeError(f"Falha ao ler política sintética em {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Política sintética inválida em {path}: conteúdo deve ser um objeto YAML")

    return _build_policy_from_data(path, source, data)


def sanitize_label(label: str | None) -> str:
    value = (label or "").strip()
    if not value:
        return "safe-check"
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value)
    value = re.sub(r"[-_.]{2,}", "-", value)
    value = value.strip("-_.")
    if not value:
        return "safe-check"
    return value[:80]


def _normalized_url(parsed) -> str:
    netloc = parsed.netloc.lower()
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment))


def _ip_is_blocked(hostname: str, blocked_networks: list[str]) -> tuple[bool, str]:
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        return False, ""
    for network in blocked_networks:
        try:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True, f"hostname is in blocked network {network}"
        except ValueError:
            continue
    return False, ""


def validate_synthetic_target(url: str, policy: dict[str, Any] | None = None, allow_unlisted: bool = False) -> dict[str, Any]:
    policy = policy or load_synthetic_target_policy()
    raw_url = (url or "").strip()
    parsed = urlparse(raw_url)
    normalized_url = _normalized_url(parsed) if parsed.scheme and parsed.netloc else raw_url

    if parsed.scheme not in {"http", "https"}:
        return {
            "allowed": False,
            "reason": "URL inválida. Use apenas http:// ou https://.",
            "hostname": parsed.hostname,
            "normalized_url": normalized_url,
            "matched_rule": "invalid_scheme",
        }
    if not parsed.hostname:
        return {
            "allowed": False,
            "reason": "URL inválida. Hostname ausente.",
            "hostname": None,
            "normalized_url": normalized_url,
            "matched_rule": "missing_hostname",
        }
    if parsed.username or parsed.password:
        return {
            "allowed": False,
            "reason": "URL inválida. Não use credenciais embutidas na URL.",
            "hostname": parsed.hostname,
            "normalized_url": normalized_url,
            "matched_rule": "userinfo",
        }

    hostname = parsed.hostname.lower()
    if hostname in policy["blocked_domains"] or any(hostname.endswith(f".{domain}") for domain in policy["blocked_domains"]):
        return {
            "allowed": False,
            "reason": f"hostname bloqueado: {hostname}",
            "hostname": hostname,
            "normalized_url": normalized_url,
            "matched_rule": "blocked_domain",
        }
    if any(hostname == suffix.lstrip(".") or hostname.endswith(suffix) for suffix in policy["blocked_suffixes"]):
        return {
            "allowed": False,
            "reason": f"hostname bloqueado por sufixo: {hostname}",
            "hostname": hostname,
            "normalized_url": normalized_url,
            "matched_rule": "blocked_suffix",
        }

    blocked_ip, ip_reason = _ip_is_blocked(hostname, policy["blocked_networks"])
    if blocked_ip:
        return {
            "allowed": False,
            "reason": f"hostname bloqueado por rede: {hostname}",
            "hostname": hostname,
            "normalized_url": normalized_url,
            "matched_rule": ip_reason,
        }

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if not ip_obj.is_global:
            return {
                "allowed": False,
                "reason": f"hostname bloqueado por escopo de IP: {hostname}",
                "hostname": hostname,
                "normalized_url": normalized_url,
                "matched_rule": "non_global_ip",
            }
        if not allow_unlisted and hostname not in policy["allowed_domains"]:
            return {
                "allowed": False,
                "reason": f"hostname não está na allowlist: {hostname}",
                "hostname": hostname,
                "normalized_url": normalized_url,
                "matched_rule": "not_allowlisted",
            }
        return {
            "allowed": True,
            "reason": "hostname permitido",
            "hostname": hostname,
            "normalized_url": normalized_url,
            "matched_rule": "allow_unlisted" if hostname not in policy["allowed_domains"] else "allowlisted",
        }

    if hostname not in policy["allowed_domains"]:
        if allow_unlisted:
            return {
                "allowed": True,
                "reason": "hostname permitido por override consciente",
                "hostname": hostname,
                "normalized_url": normalized_url,
                "matched_rule": "allow_unlisted",
            }
        return {
            "allowed": False,
            "reason": f"hostname não está na allowlist: {hostname}",
            "hostname": hostname,
            "normalized_url": normalized_url,
            "matched_rule": "not_allowlisted",
        }

    return {
        "allowed": True,
        "reason": "hostname permitido",
        "hostname": hostname,
        "normalized_url": normalized_url,
        "matched_rule": "allowlisted",
    }
