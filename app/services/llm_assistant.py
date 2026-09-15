from __future__ import annotations

import logging
import os
import re
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
OPENAI_AGENTS_PROVIDER = "openai_agents"

_SAFE_CONTEXT = (
    "Você é o assistente conversacional do RouteBrain, uma ferramenta de análise operacional de rede. "
    "Responda em português brasileiro, de forma curta e prática. Você pode explicar que o RouteBrain ajuda "
    "com IPs, domínios, ASN, BGP, observed destinations, MikroTik, baseline, traceroute, tendências e relatórios. "
    "Não afirme que executou medições. Não invente resultados. Sugira perguntas que o operador pode fazer."
)

_TECHNICAL_TERMS_RE = re.compile(
    r"\b(ip|asn|as\d+|bgp|rota|roteamento|route|traceroute|trace|ping|dns|dom[ií]nio|prefixo|"
    r"baseline|mikrotik|observed|destinations?|hop|hops?|ptt|ix\.?br|invent[aá]rio|peer|peering|"
    r"facebook|youtube|google|cloudflare|simular|navegar|acesso)\b",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b", re.IGNORECASE)
_EXPLICIT_ASN_RE = re.compile(r"\b(?:ASN|AS)\s*([1-9]\d{0,9})\b", re.IGNORECASE)
_URL_WITH_QUERY_RE = re.compile(r"\bhttps?://[^\s?]+[?][^\s]+", re.IGNORECASE)
_TOKEN_RE = re.compile(
    r"(?i)\b(openai_api_key|api[_-]?key|authorization|bearer|token|secret|password|passwd|senha|"
    r"client_secret|access_token|refresh_token)\b\s*[:=]\s*['\"]?[^'\"\s]+"
)
_LONG_SECRET_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{20,}|[A-Za-z0-9_=-]{32,})\b")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "sim"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def is_llm_assistant_enabled() -> bool:
    provider = os.getenv("ROUTEBRAIN_LLM_PROVIDER", "openai").strip().lower()
    return _env_bool("ROUTEBRAIN_LLM_ASSISTANT_ENABLED", False) and provider in {"openai", OPENAI_AGENTS_PROVIDER}


def build_safe_assistant_context() -> dict[str, Any]:
    return {
        "description": _SAFE_CONTEXT,
        "capabilities": [
            "verificar IP ou domínio",
            "consultar ASN e BGP",
            "analisar observed destinations",
            "comparar baseline",
            "mostrar tendências",
            "explicar traceroute/ping sob confirmação",
            "orientar relatórios operacionais",
        ],
    }


def sanitize_user_message_for_llm(message: str) -> str:
    max_chars = _env_int("ROUTEBRAIN_LLM_MAX_INPUT_CHARS", 2000, minimum=100, maximum=8000)
    text = str(message or "")[:max_chars]
    text = _URL_WITH_QUERY_RE.sub("[url_removida]", text)
    text = _TOKEN_RE.sub(lambda match: f"{match.group(1)}=[redigido]", text)
    text = _LONG_SECRET_RE.sub("[token_redigido]", text)
    text = re.sub(r"(?is)-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[bloco_redigido]", text)
    text = re.sub(r"(?im)^.*(?:authorization|cookie|set-cookie|x-api-key)\s*:.*$", "[header_redigido]", text)
    return " ".join(text.split()).strip()


def _normalized_text(question: str) -> str:
    text = " ".join(str(question or "").strip().lower().split())
    for source, target in {
        "á": "a",
        "à": "a",
        "ã": "a",
        "â": "a",
        "é": "e",
        "ê": "e",
        "í": "i",
        "ó": "o",
        "õ": "o",
        "ô": "o",
        "ú": "u",
        "ç": "c",
    }.items():
        text = text.replace(source, target)
    return text


def _contains_operational_entity(question: str) -> bool:
    return bool(_IP_RE.search(question) or _DOMAIN_RE.search(question) or _EXPLICIT_ASN_RE.search(question))


def _conversational_intent(question: str) -> str:
    normalized = _normalized_text(question)
    if normalized in {"ola", "oi", "opa", "bom dia", "boa tarde", "boa noite", "e ai", "eai"}:
        return "general_greeting"
    if normalized in {"teste", "test", "ping"}:
        return "general_test"
    if any(term in normalized for term in ("o que voce sabe fazer", "o que vc sabe fazer", "quais perguntas", "como pergunto", "me ajuda", "ajuda", "help")):
        return "help_prompt"
    return "conversational_help"


def should_use_llm_assistant(question: str, parsed_context: dict[str, Any] | None = None) -> bool:
    text = str(question or "").strip()
    if not text:
        return True
    if parsed_context and parsed_context.get("intent") not in {None, "", "general"}:
        return False
    lowered = _normalized_text(text)
    if any(term in lowered for term in ("unknown hop", "unknown hops", "desconhecid", "hops externos", "routers externos", "roteadores externos", "ptt", "ix.br", "ixp", "hops", "router", "routers")):
        return False
    meta_help_terms = (
        "me sugere",
        "sugere perguntas",
        "sugerir perguntas",
        "sugira perguntas",
        "formular uma pergunta",
        "como formular",
        "tipos de pergunta",
        "que tipos de pergunta",
        "quais tipos de pergunta",
        "explique a diferenca",
        "explica a diferenca",
        "qual a diferenca",
        "diferença entre",
        "diferenca entre",
    )
    if any(term in lowered for term in meta_help_terms) and not _contains_operational_entity(text):
        return True
    if _contains_operational_entity(text):
        return any(term in lowered for term in ("me ajuda", "como pergunto", "explique", "explica", "nao entendi"))
    if any(term in lowered for term in ("me ajuda a formular", "como pergunto", "explique melhor", "explica melhor", "nao entendi")):
        return True
    if len(text) <= 80 and not _TECHNICAL_TERMS_RE.search(text):
        return True
    if any(term in lowered for term in ("o que voce sabe fazer", "o que vc sabe fazer", "me ajuda", "help", "ajuda")):
        return True
    return False


def fallback_conversational_answer(question: str) -> str:
    intent = _conversational_intent(question)
    if intent == "general_greeting":
        return (
            "Olá! Sou o RouteBrain. Posso ajudar com perguntas operacionais de rede, BGP, ASN, destinos observados, "
            "traceroute, baseline e tendências. Experimente perguntar: 'verifica se o 8.8.8.8 está operacional', "
            "'qual rota para youtube.com' ou 'quais destinos minha rede mais acessou?'"
        )
    if intent == "general_test":
        return (
            "Teste recebido. A API está respondendo. Para validar o RouteBrain com uma pergunta operacional, experimente: "
            "'verifica se o 8.8.8.8 está operacional' ou 'qual rota para youtube.com'."
        )
    if intent == "help_prompt":
        return (
            "Posso verificar IP/domínio, consultar ASN/BGP, analisar observed destinations, gerar relatório, comparar "
            "baseline, mostrar tendências e orientar traceroute/ping sob confirmação. Exemplos: 'qual rota para youtube.com', "
            "'Me mostra como o ASN 15169 enxerga o IP 203.0.113.42' ou 'quais destinos minha rede mais acessou?'."
        )
    return (
        "Posso ajudar a formular a pergunta. Use um alvo claro, como IP, domínio ou ASN. Exemplos: "
        "'verifica se o 8.8.8.8 está operacional', 'qual rota para youtube.com' ou "
        "'verificar se houve mudança de roteamento para o ASN 15169'."
    )


def _sanitize_error(exc: Exception) -> str:
    detail = sanitize_user_message_for_llm(str(exc).strip())[:160]
    return f"{exc.__class__.__name__}: {detail}" if detail else exc.__class__.__name__


def _extract_openai_text(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"].strip()
    parts: list[str] = []
    for item in payload.get("output") or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content") or []:
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                parts.append(content["text"])
    return "\n".join(part.strip() for part in parts if part and part.strip()).strip()


def _trim_output(text: str) -> str:
    max_chars = _env_int("ROUTEBRAIN_LLM_MAX_OUTPUT_CHARS", 1200, minimum=200, maximum=4000)
    text = str(text or "").strip()
    return text if len(text) <= max_chars else text[: max_chars - 3].rstrip() + "..."


def _fallback_agent_observability(
    *,
    enabled: bool,
    error: str | None = None,
    safety_notes: list[str] | None = None,
) -> dict[str, Any]:
    guardrails = [error] if error in {"blocked_sensitive_input", "blocked_active_action_input"} else []
    return {
        "enabled": enabled,
        "used_agent": False,
        "provider": "fallback",
        "model": None,
        "primary_agent": None,
        "final_agent": None,
        "handoffs": [],
        "tools_called": [],
        "guardrails_triggered": guardrails,
        "safety_notes": safety_notes or [],
        "response_type": "conversational_guidance",
        "active_action_executed": False,
        "evidence_source": "fallback",
        "trace_available": False,
        "trace_id": None,
        "trace_safe_summary": {
            "summary": "Fallback local; sem trace do Agents SDK.",
            "fallback_reason": error,
        },
    }


def generate_conversational_answer(question: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    model = os.getenv("ROUTEBRAIN_LLM_MODEL", "").strip() or DEFAULT_OPENAI_MODEL
    provider = os.getenv("ROUTEBRAIN_LLM_PROVIDER", "openai").strip().lower()
    fallback = {
        "provider": "fallback",
        "model": model,
        "used_llm": False,
        "error": None,
        "answer": fallback_conversational_answer(question),
        "suggested_action_plan": None,
        "agent_observability": _fallback_agent_observability(
            enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
        ),
    }
    if provider == OPENAI_AGENTS_PROVIDER or _env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False):
        try:
            from app.services.agents.routebrain_conversation_agent import generate_conversation_with_agent

            result = generate_conversation_with_agent(question)
            return {
                "provider": result.provider,
                "model": result.model,
                "used_llm": result.used_llm,
                "fallback": result.fallback,
                "error": result.error,
                "answer": result.answer,
                "suggested_questions": result.suggested_questions,
                "intent_hint": result.intent_hint,
                "safety_notes": result.safety_notes,
                "suggested_action_plan": result.suggested_action_plan,
                "agent_observability": (
                    result.agent_observability.model_dump()
                    if result.agent_observability is not None
                    else _fallback_agent_observability(
                        enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
                        error=result.error,
                        safety_notes=result.safety_notes,
                    )
                ),
            }
        except Exception as exc:
            error = _sanitize_error(exc)
            logger.warning("llm_assistant provider=%s model=%s used_llm=false error=%s", OPENAI_AGENTS_PROVIDER, model, error)
            return {
                **fallback,
                "provider": OPENAI_AGENTS_PROVIDER,
                "error": error,
                "agent_observability": _fallback_agent_observability(
                    enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
                    error=error,
                ),
            }
    if not is_llm_assistant_enabled():
        return fallback
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return {
            **fallback,
            "error": "missing_openai_api_key",
            "agent_observability": _fallback_agent_observability(
                enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
                error="missing_openai_api_key",
            ),
        }

    timeout = _env_int("ROUTEBRAIN_LLM_TIMEOUT_SECONDS", 20, minimum=1, maximum=60)
    max_output_chars = _env_int("ROUTEBRAIN_LLM_MAX_OUTPUT_CHARS", 1200, minimum=200, maximum=4000)
    started = time.monotonic()
    try:
        response = requests.post(
            OPENAI_RESPONSES_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "instructions": build_safe_assistant_context()["description"],
                "input": [
                    {
                        "role": "user",
                        "content": (
                            "Pergunta do operador, já sanitizada. Responda só com orientação textual, "
                            "sem executar ou afirmar medições:\n"
                            f"{sanitize_user_message_for_llm(question)}"
                        ),
                    }
                ],
                "max_output_tokens": max(80, min(500, max_output_chars // 3)),
                "temperature": 0.2,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        answer = _trim_output(_extract_openai_text(response.json()))
        if not answer:
            raise RuntimeError("empty_openai_response")
        elapsed = round(time.monotonic() - started, 3)
        logger.info("llm_assistant provider=openai model=%s used_llm=true elapsed=%s", model, elapsed)
        return {
            "provider": "openai",
            "model": model,
            "used_llm": True,
            "error": None,
            "answer": answer,
            "suggested_action_plan": None,
            "agent_observability": {
                "enabled": False,
                "used_agent": False,
                "provider": "openai",
                "model": model,
                "primary_agent": None,
                "final_agent": None,
                "handoffs": [],
                "tools_called": [],
                "guardrails_triggered": [],
                "safety_notes": [],
                "response_type": "conversational_guidance",
                "active_action_executed": False,
                "evidence_source": "fallback",
                "trace_available": False,
                "trace_id": None,
                "trace_safe_summary": {"summary": "Resposta via Responses API, sem Agents SDK."},
            },
        }
    except Exception as exc:
        elapsed = round(time.monotonic() - started, 3)
        error = _sanitize_error(exc)
        logger.warning("llm_assistant provider=openai model=%s used_llm=false elapsed=%s error=%s", model, elapsed, error)
        return {
            **fallback,
            "error": error,
            "agent_observability": _fallback_agent_observability(
                enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
                error=error,
            ),
        }
