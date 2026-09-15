from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

ROUTEVIEWS_METADATA_URL = "https://api.routeviews.org/meta/collectors"


class RouteViewsMetadataError(RuntimeError):
    """Raised when RouteViews metadata cannot be fetched or parsed."""


def _load_environment() -> None:
    project_root = Path(__file__).resolve().parents[2]
    load_dotenv(project_root / ".env")
    load_dotenv()


def get_routeviews_collector_name() -> str:
    _load_environment()
    return os.getenv("ROUTEVIEWS_COLLECTOR", "route-views2")


def _extract_data_types(collector_data: dict[str, Any]) -> dict[str, Any]:
    data_types = collector_data.get("dataTypes")
    if not isinstance(data_types, dict):
        raise RouteViewsMetadataError("Resposta da API sem dataTypes para o coletor informado.")

    ribs = data_types.get("ribs")
    updates = data_types.get("updates")

    if not isinstance(ribs, dict):
        raise RouteViewsMetadataError("Resposta da API sem dados de ribs para o coletor informado.")
    if not isinstance(updates, dict):
        raise RouteViewsMetadataError("Resposta da API sem dados de updates para o coletor informado.")

    return {
        "ribs": {
            "latestDumpTime": ribs.get("latestDumpTime"),
            "latestDumpTimeISO8601": ribs.get("latestDumpTimeISO8601"),
            "latestDumpFile": ribs.get("latestDumpFile"),
            "dumpPeriod": ribs.get("dumpPeriod"),
        },
        "updates": {
            "latestDumpTime": updates.get("latestDumpTime"),
            "latestDumpTimeISO8601": updates.get("latestDumpTimeISO8601"),
            "latestDumpFile": updates.get("latestDumpFile"),
            "dumpPeriod": updates.get("dumpPeriod"),
        },
    }


def fetch_routeviews_metadata() -> dict[str, Any]:
    collector_name = get_routeviews_collector_name()

    try:
        response = requests.get(ROUTEVIEWS_METADATA_URL, timeout=30)
    except requests.RequestException as exc:
        raise RouteViewsMetadataError(f"Falha ao consultar {ROUTEVIEWS_METADATA_URL}: {exc}") from exc

    if response.status_code != 200:
        raise RouteViewsMetadataError(
            f"API RouteViews respondeu com status {response.status_code} em {ROUTEVIEWS_METADATA_URL}."
        )

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise RouteViewsMetadataError("API RouteViews retornou JSON inválido.") from exc

    if not isinstance(payload, dict):
        raise RouteViewsMetadataError("Resposta da API em formato inesperado.")

    data = payload.get("data")
    if not isinstance(data, dict):
        raise RouteViewsMetadataError("Resposta da API sem campo data.")

    collectors = data.get("collectors")
    if not isinstance(collectors, dict):
        raise RouteViewsMetadataError("Resposta da API sem campo data.collectors.")

    collector_data = collectors.get(collector_name)
    if not isinstance(collector_data, dict):
        available = ", ".join(sorted(collectors.keys()))
        raise RouteViewsMetadataError(
            f"Coletor '{collector_name}' não encontrado em data.collectors. Disponíveis: {available}"
        )

    data_types = _extract_data_types(collector_data)

    return {
        "collector": collector_name,
        "project": collector_data.get("project"),
        "baseURL": collector_data.get("baseURL"),
        **data_types,
    }
