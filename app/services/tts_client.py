from __future__ import annotations

import os
import re
from typing import Any

import requests


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def is_tts_enabled() -> bool:
    return _truthy(_env("ROUTEBRAIN_TTS_ENABLED", "false"))


def get_tts_config() -> dict[str, Any]:
    return {
        "enabled": is_tts_enabled(),
        "base_url": _env("ROUTEBRAIN_TTS_BASE_URL", "http://127.0.0.1:8090").rstrip("/"),
        "default_provider": _env("ROUTEBRAIN_TTS_PROVIDER", "mock"),
        "language": _env("ROUTEBRAIN_TTS_LANGUAGE", "pt-BR") or "pt-BR",
        "voice": _env("ROUTEBRAIN_TTS_VOICE", ""),
        "timeout_seconds": int(_env("ROUTEBRAIN_TTS_TIMEOUT_SECONDS", "60") or "60"),
    }


def _safe_join(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def get_tts_health() -> dict[str, Any]:
    config = get_tts_config()
    payload: dict[str, Any] = {
        "enabled": config["enabled"],
        "base_url": config["base_url"],
        "default_provider": config["default_provider"],
        "reachable": False,
        "tts_health": None,
        "providers": [],
    }
    if not config["enabled"]:
        return payload
    try:
        response = requests.get(_safe_join(config["base_url"], "/health"), timeout=min(config["timeout_seconds"], 20))
        response.raise_for_status()
        payload["reachable"] = True
        payload["tts_health"] = response.json()
    except Exception as exc:
        payload["tts_health"] = {"status": "error", "message": "TTS indisponível.", "detail": str(exc)}
    try:
        response = requests.get(_safe_join(config["base_url"], "/api/providers"), timeout=min(config["timeout_seconds"], 20))
        response.raise_for_status()
        data = response.json()
        payload["providers"] = data.get("providers") or []
    except Exception:
        payload["providers"] = []
    return payload


def _normalize_audio_url(base_url: str, audio_url: str | None) -> str | None:
    if not audio_url:
        return None
    if audio_url.startswith("http://") or audio_url.startswith("https://"):
        return audio_url
    return _safe_join(base_url, audio_url)


def extract_audio_filename(audio_url: str | None, fallback: str | None = None) -> str | None:
    if fallback:
        candidate = str(fallback).strip()
        if candidate:
            return candidate
    if not audio_url:
        return None
    match = re.search(r"/generated/([^/?#]+)$", audio_url)
    if match:
        return match.group(1)
    if audio_url.startswith("http://") or audio_url.startswith("https://"):
        path = audio_url.split("?", 1)[0].split("#", 1)[0]
        return path.rsplit("/", 1)[-1] or None
    path = audio_url.split("?", 1)[0].split("#", 1)[0]
    return path.rsplit("/", 1)[-1] or None


def generate_question_audio(
    text: str,
    provider: str | None = None,
    voice: str | None = None,
    language: str | None = None,
) -> dict[str, Any]:
    config = get_tts_config()
    if not config["enabled"]:
        return {
            "status": "disabled",
            "provider": provider or config["default_provider"],
            "audio_url": None,
            "filename": None,
            "mime_type": None,
            "message": "TTS desabilitado. Configure ROUTEBRAIN_TTS_ENABLED=true.",
        }

    payload = {
        "text": text,
        "provider": provider or config["default_provider"],
        "language": language or config["language"],
        "voice": voice if voice is not None else config["voice"],
        "speed": 1.0,
    }
    try:
        response = requests.post(
            _safe_join(config["base_url"], "/api/generate-audio"),
            json=payload,
            timeout=config["timeout_seconds"],
        )
    except requests.RequestException as exc:
        return {
            "status": "error",
            "provider": payload["provider"],
            "audio_url": None,
            "filename": None,
            "mime_type": None,
            "message": "TTS indisponível no momento.",
        }

    try:
        data = response.json()
    except Exception:
        data = {}

    if not response.ok:
        message = data.get("detail") or data.get("message") or "Falha ao gerar áudio."
        return {
            "status": "error",
            "provider": payload["provider"],
            "audio_url": None,
            "filename": None,
            "mime_type": None,
            "message": message,
        }

    audio_url = _normalize_audio_url(config["base_url"], data.get("audio_url"))
    filename = data.get("filename")
    mime_type = "audio/mpeg"
    if isinstance(filename, str) and filename.lower().endswith(".wav"):
        mime_type = "audio/wav"
    elif isinstance(filename, str) and filename.lower().endswith(".mp3"):
        mime_type = "audio/mpeg"
    return {
        "status": "ok",
        "provider": data.get("provider") or payload["provider"],
        "audio_url": audio_url,
        "filename": filename,
        "mime_type": mime_type,
        "message": "Áudio gerado com sucesso.",
    }
