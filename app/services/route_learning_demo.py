from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DEMO_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "reports" / "route_learning_demo_session_8_8_8_8_20260608T051248Z.json"


def get_route_learning_demo_payload() -> dict[str, Any]:
    if not _DEMO_PATH.exists():
        raise ValueError("Payload demonstrativo da Route Learning não encontrado.")
    with _DEMO_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError("Payload demonstrativo inválido.")
    return payload

