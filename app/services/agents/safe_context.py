from __future__ import annotations

import os
import re
from urllib.parse import urlsplit, urlunsplit


SAFE_CONTEXT_TEXT = (
    "RouteBrain é uma ferramenta de análise operacional de rede. Ajuda com IPs, domínios, ASN, BGP, "
    "destinos observados, MikroTik, baseline, traceroute, tendências e relatórios. O assistente "
    "conversacional não executa medições nem ações. Ele apenas explica, orienta e sugere perguntas. "
    "Ações ativas exigem backend RouteBrain, RBAC e confirmação explícita."
)

_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(authorization|bearer|password|passwd|senha|token|api[_-]?key|openai_api_key|secret|"
    r"client_secret|access_token|refresh_token)\b\s*[:=]\s*['\"]?[^'\"\s]+"
)
_SECRET_HEADER_RE = re.compile(
    r"(?im)^(.*\b(?:authorization|cookie|set-cookie|x-api-key)\b\s*:\s*).*$"
)
_URL_RE = re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE)
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_=-]{40,}\b")


def _max_input_chars() -> int:
    raw = os.getenv("ROUTEBRAIN_LLM_MAX_INPUT_CHARS", "2000").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 2000
    return max(100, min(8000, value))


def build_routebrain_safe_context() -> str:
    return SAFE_CONTEXT_TEXT


def _strip_url_query(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return "[url_removida]"
    if not parsed.netloc:
        return "[url_removida]"
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return safe_url.rstrip("/") if parsed.path in {"", "/"} else safe_url


def sanitize_user_message_for_agent(message: str) -> str:
    text = str(message or "")[: _max_input_chars()]
    text = re.sub(r"(?is)-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[bloco_redigido]", text)
    text = _SECRET_HEADER_RE.sub(r"\1[redigido]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redigido]", text)
    text = _OPENAI_KEY_RE.sub("[token_redigido]", text)
    text = _URL_RE.sub(_strip_url_query, text)
    text = _LONG_TOKEN_RE.sub("[token_redigido]", text)
    return " ".join(text.split()).strip()

