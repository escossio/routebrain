from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
import logging
import os
import time
from app.services.agents.guardrails import (
    postflight_agent_output,
    preflight_agent_input,
    requires_uncertainty_note,
    sanitize_agent_safety_notes,
    sanitize_agent_suggested_questions,
)
from app.services.agents.safe_context import build_routebrain_safe_context, sanitize_user_message_for_agent
from app.services.agents.schemas import AgentObservability, ConversationAgentResult, ConversationAgentStructuredOutput

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-4.1-mini"
PROVIDER = "openai_agents"
PRIMARY_AGENT = "RouteBrainConversationAgent"

_INSTRUCTIONS = """
Você é o RouteBrainConversationAgent.
Responda sempre em português brasileiro, de forma curta, prática e operacional.
Explique o que o RouteBrain faz e ajude o operador a formular perguntas úteis.
Não execute coleta, ping, traceroute, enrich, baseline, DevTools, navegação sintética ou qualquer ação sensível.
Não afirme que executou medições ou que consultou dados operacionais ao vivo.
Não invente resultados de rede, ASN, BGP, MikroTik, baseline ou traceroute.
Não gere comandos destrutivos, não peça segredo e não aceite credenciais.
Se o operador pedir execução ativa, explique que só o backend RouteBrain pode executar com RBAC e confirmação explícita.
Se não houver evidência operacional fornecida pelo backend, use linguagem de incerteza e diga que não pode afirmar resultado.
Ações ativas exigem backend RouteBrain, RBAC e confirmação explícita.
Quando não houver evidência, use linguagem de incerteza.
Se a pergunta sair do escopo, diga que pode ajudar com rede, BGP, ASN, destinos observados, traceroute e baseline.
Tools read-only podem ser usadas somente para explicar capacidades, sugerir perguntas e obter contexto fixo seguro.
Não use tools para medir, coletar, consultar MikroTik, executar ping/traceroute, enriquecer, alterar baseline ou navegar.
Handoffs especializados podem ser usados somente para explicar, classificar e reformular perguntas.
Mesmo após handoff, nenhum agente executa ação operacional ou consulta dado sensível.
Retorne saída estruturada com: answer, suggested_questions, intent_hint e safety_notes.
Em suggested_questions, sugira no máximo 3 perguntas úteis e seguras.
Em intent_hint, use um destes valores quando fizer sentido: general_greeting, general_test, help_prompt, conversational_help.
Em safety_notes, registre somente notas curtas sobre limites de segurança, incerteza ou necessidade de confirmação.
"""


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
        value = default
    return max(minimum, min(maximum, value))


def _trim_output(text: str) -> str:
    max_chars = _env_int("ROUTEBRAIN_LLM_MAX_OUTPUT_CHARS", 1200, minimum=200, maximum=4000)
    text = str(text or "").strip()
    return text if len(text) <= max_chars else text[: max_chars - 3].rstrip() + "..."


def _trim_list(items: list[str], *, max_items: int = 3, max_chars: int = 220) -> list[str]:
    cleaned: list[str] = []
    for item in items:
        text = " ".join(str(item or "").split()).strip()
        if not text:
            continue
        cleaned.append(text if len(text) <= max_chars else text[: max_chars - 3].rstrip() + "...")
        if len(cleaned) >= max_items:
            break
    return cleaned


def _dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    for item in items:
        text = " ".join(str(item or "").split()).strip()
        if text and text not in result:
            result.append(text)
    return result


def _agent_observability(
    *,
    model: str | None,
    used_agent: bool,
    fallback: bool,
    safety_notes: list[str] | None = None,
    guardrails_triggered: list[str] | None = None,
    final_agent: str | None = None,
    handoffs: list[str] | None = None,
    tools_called: list[str] | None = None,
    error: str | None = None,
) -> AgentObservability:
    trace_enabled = _env_bool("ROUTEBRAIN_AGENTS_TRACE_ENABLED", True)
    safe_summary: dict[str, object] = {
        "summary": "Resumo seguro; trace bruto e prompt completo não são expostos.",
        "tools_capture": "unavailable" if used_agent else "not_applicable",
        "handoffs_capture": "unavailable" if used_agent else "not_applicable",
    }
    if fallback and error:
        safe_summary["fallback_reason"] = error
    if used_agent:
        safe_summary["active_action_policy"] = "Agent apenas orienta; execução ativa fica no backend RouteBrain."
    return AgentObservability(
        enabled=_env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False),
        used_agent=used_agent,
        provider=PROVIDER,
        model=model,
        primary_agent=PRIMARY_AGENT if used_agent else None,
        final_agent=final_agent or (PRIMARY_AGENT if used_agent else None),
        handoffs=_dedupe(handoffs or []),
        tools_called=_dedupe(tools_called or []),
        guardrails_triggered=_dedupe(guardrails_triggered or []),
        safety_notes=_trim_list(safety_notes or [], max_items=5),
        response_type="conversational_guidance",
        active_action_executed=False,
        evidence_source="agent" if used_agent else "fallback",
        trace_available=bool(trace_enabled and used_agent),
        trace_id=None,
        trace_safe_summary=safe_summary,
    )


def _sanitize_error(exc: Exception) -> str:
    detail = sanitize_user_message_for_agent(str(exc).strip())[:160]
    return f"{exc.__class__.__name__}: {detail}" if detail else exc.__class__.__name__


def _fallback_answer(question: str, *, error: str | None = None, safety_note: str | None = None) -> ConversationAgentResult:
    normalized = " ".join(str(question or "").strip().lower().split())
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
        normalized = normalized.replace(source, target)

    if safety_note:
        answer = safety_note
        intent_hint = "safety_blocked"
    elif normalized in {"ola", "oi", "opa", "bom dia", "boa tarde", "boa noite", "e ai", "eai"}:
        answer = (
            "Olá! Sou o RouteBrain. Posso ajudar com IPs, domínios, ASN, BGP, destinos observados, "
            "baseline, traceroute e tendências. Eu oriento; ações ativas dependem do backend com confirmação."
        )
        intent_hint = "general_greeting"
    elif normalized in {"teste", "test", "ping"}:
        answer = (
            "Teste recebido. A API conversacional está respondendo. Para validar uma consulta operacional, use algo como "
            "'verifica se o 8.8.8.8 está operacional'."
        )
        intent_hint = "general_test"
    elif "o que voce sabe fazer" in normalized or "ajuda" in normalized or "help" in normalized:
        answer = (
            "Posso orientar perguntas sobre IP/domínio, ASN/BGP, destinos observados, baseline, traceroute e relatórios. "
            "Exemplos: 'qual rota para youtube.com' ou 'como o ASN 15169 enxerga o IP 203.0.113.42'."
        )
        intent_hint = "help_prompt"
    else:
        answer = (
            "Posso ajudar a formular a pergunta. Informe um alvo claro, como IP, domínio ou ASN. "
            "Exemplo: 'Me ajuda a verificar a rota para youtube.com'."
        )
        intent_hint = "conversational_help"

    guardrails_triggered = [error] if error in {"blocked_sensitive_input", "blocked_active_action_input"} else []
    safety_notes = [safety_note] if safety_note else []
    return ConversationAgentResult(
        answer=answer,
        suggested_questions=[
            "verifica se o 8.8.8.8 está operacional",
            "qual rota para youtube.com",
            "Me mostra como o ASN 15169 enxerga o IP 203.0.113.42",
        ],
        intent_hint=intent_hint,
        safety_notes=safety_notes,
        used_llm=False,
        provider=PROVIDER,
        model=os.getenv("ROUTEBRAIN_LLM_MODEL", "").strip() or DEFAULT_MODEL,
        fallback=True,
        error=error,
        agent_observability=_agent_observability(
            model=os.getenv("ROUTEBRAIN_LLM_MODEL", "").strip() or DEFAULT_MODEL,
            used_agent=False,
            fallback=True,
            safety_notes=safety_notes,
            guardrails_triggered=guardrails_triggered,
            error=error,
        ),
        suggested_action_plan=None,
    )


def _coerce_structured_output(value: object) -> ConversationAgentStructuredOutput:
    if isinstance(value, ConversationAgentStructuredOutput):
        return value
    if isinstance(value, dict):
        return ConversationAgentStructuredOutput.model_validate(value)
    if isinstance(value, str):
        return ConversationAgentStructuredOutput(answer=value)
    return ConversationAgentStructuredOutput.model_validate(value)


def _build_read_only_tools() -> list[object]:
    from agents import function_tool

    from app.services.agents.tools import (
        explain_question_type,
        get_routebrain_capabilities,
        maybe_get_safe_system_context,
        suggest_operational_questions,
    )

    return [
        function_tool(get_routebrain_capabilities),
        function_tool(suggest_operational_questions),
        function_tool(explain_question_type),
        function_tool(maybe_get_safe_system_context),
    ]


def _build_handoffs(model: str) -> list[object]:
    from agents import handoff

    from app.services.agents.specialized_agents import build_specialized_handoff_agents

    return [handoff(agent) for agent in build_specialized_handoff_agents(model)]


def _run_agents_sdk(
    question: str,
    model: str,
    max_turns: int,
    enable_tools: bool,
    enable_handoffs: bool,
) -> tuple[ConversationAgentStructuredOutput, dict[str, str]]:
    from agents import Agent, Runner, set_tracing_disabled

    trace_enabled = _env_bool("ROUTEBRAIN_AGENTS_TRACE_ENABLED", True)
    include_sensitive = _env_bool("ROUTEBRAIN_AGENTS_TRACE_INCLUDE_SENSITIVE", False)
    set_tracing_disabled(not trace_enabled or include_sensitive)

    agent = Agent(
        name="RouteBrainConversationAgent",
        instructions=f"{_INSTRUCTIONS}\n\nContexto seguro do produto:\n{build_routebrain_safe_context()}",
        model=model,
        output_type=ConversationAgentStructuredOutput,
        tools=_build_read_only_tools() if enable_tools else [],
        handoffs=_build_handoffs(model) if enable_handoffs else [],
    )
    result = Runner.run_sync(agent, input=question, max_turns=max_turns)
    final_output = getattr(result, "final_output", None)
    if final_output is None:
        final_output = getattr(result, "output", None)
    structured = _coerce_structured_output(final_output)
    final_agent = getattr(getattr(result, "last_agent", None), "name", None)
    return structured, {"final_agent": final_agent or PRIMARY_AGENT}


def generate_conversation_with_agent(question: str) -> ConversationAgentResult:
    model = os.getenv("ROUTEBRAIN_LLM_MODEL", "").strip() or DEFAULT_MODEL
    if not _env_bool("ROUTEBRAIN_AGENTS_SDK_ENABLED", False):
        return _fallback_answer(question, error="agents_sdk_disabled")
    enable_tools = _env_bool("ROUTEBRAIN_AGENTS_ENABLE_TOOLS", False)
    enable_handoffs = _env_bool("ROUTEBRAIN_AGENTS_ENABLE_HANDOFFS", False)
    if not os.getenv("OPENAI_API_KEY", "").strip():
        return _fallback_answer(question, error="missing_openai_api_key")

    allowed, fallback_message = preflight_agent_input(question)
    if not allowed:
        error = "blocked_active_action_input" if "execução depende do backend RouteBrain" in str(fallback_message or "") else "blocked_sensitive_input"
        return _fallback_answer(question, error=error, safety_note=fallback_message)

    timeout = _env_int("ROUTEBRAIN_LLM_TIMEOUT_SECONDS", 20, minimum=1, maximum=60)
    max_turns = _env_int("ROUTEBRAIN_AGENTS_MAX_TURNS", 3, minimum=1, maximum=10)
    sanitized_question = sanitize_user_message_for_agent(question)
    started = time.monotonic()
    try:
        executor = ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(_run_agents_sdk, sanitized_question, model, max_turns, enable_tools, enable_handoffs)
            structured, sdk_metadata = future.result(timeout=timeout)
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        answer = _trim_output(postflight_agent_output(structured.answer))
        if not answer:
            raise RuntimeError("empty_agents_response")
        suggested_questions = _trim_list(sanitize_agent_suggested_questions(structured.suggested_questions))
        if not suggested_questions:
            suggested_questions = [
                "verifica se o 8.8.8.8 está operacional",
                "qual rota para youtube.com",
                "Me mostra como o ASN 15169 enxerga o IP 203.0.113.42",
            ]
        safety_notes = _trim_list(sanitize_agent_safety_notes(structured.safety_notes), max_items=5)
        if requires_uncertainty_note(answer, safety_notes):
            safety_notes = _trim_list(
                [*safety_notes, "Sem evidência operacional do backend, esta resposta é apenas orientação conversacional."],
                max_items=5,
            )
        elapsed = round(time.monotonic() - started, 3)
        logger.info("llm_assistant provider=%s model=%s used_llm=true elapsed=%s", PROVIDER, model, elapsed)
        guardrails_triggered: list[str] = []
        postflight_answer = postflight_agent_output(structured.answer)
        if postflight_answer != structured.answer:
            guardrails_triggered.append("output_redaction")
        if any("Sem evidência operacional do backend" in note for note in safety_notes):
            guardrails_triggered.append("operational_uncertainty_note")
        return ConversationAgentResult(
            answer=answer,
            suggested_questions=suggested_questions,
            intent_hint=structured.intent_hint,
            safety_notes=safety_notes,
            used_llm=True,
            provider=PROVIDER,
            model=model,
            fallback=False,
            error=None,
            agent_observability=_agent_observability(
                model=model,
                used_agent=True,
                fallback=False,
                safety_notes=safety_notes,
                guardrails_triggered=guardrails_triggered,
                final_agent=str(sdk_metadata.get("final_agent") or PRIMARY_AGENT),
            ),
            suggested_action_plan=structured.suggested_action_plan.model_dump() if structured.suggested_action_plan else None,
        )
    except TimeoutError as exc:
        elapsed = round(time.monotonic() - started, 3)
        logger.warning("llm_assistant provider=%s model=%s used_llm=false elapsed=%s error=timeout", PROVIDER, model, elapsed)
        return _fallback_answer(question, error=_sanitize_error(exc) or "timeout")
    except Exception as exc:
        elapsed = round(time.monotonic() - started, 3)
        error = _sanitize_error(exc)
        logger.warning("llm_assistant provider=%s model=%s used_llm=false elapsed=%s error=%s", PROVIDER, model, elapsed, error)
        return _fallback_answer(question, error=error)


async def generate_conversation_with_agent_async(question: str) -> ConversationAgentResult:
    return generate_conversation_with_agent(question)
