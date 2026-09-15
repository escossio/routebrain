from __future__ import annotations

from app.services.agents.safe_context import build_routebrain_safe_context, sanitize_user_message_for_agent


def get_routebrain_capabilities() -> dict[str, object]:
    """Return a safe, static list of RouteBrain capabilities."""
    return {
        "capabilities": [
            "explicar perguntas sobre IPs públicos",
            "orientar consultas de rota para domínios",
            "orientar consultas ASN/BGP",
            "explicar destinos observados",
            "explicar baseline e tendências",
            "explicar quando ping/traceroute exigem confirmação explícita",
            "orientar relatórios operacionais",
        ],
        "limits": [
            "o assistente conversacional não executa medições",
            "o assistente conversacional não coleta dados da MikroTik",
            "ações ativas dependem do backend RouteBrain, RBAC e confirmação explícita",
        ],
    }


def suggest_operational_questions(topic: str) -> dict[str, object]:
    """Suggest safe RouteBrain questions for a topic without executing anything."""
    safe_topic = sanitize_user_message_for_agent(topic)[:120]
    topic_lower = safe_topic.lower()
    if "asn" in topic_lower or "bgp" in topic_lower:
        questions = [
            "Me mostra como o ASN 15169 enxerga o IP 203.0.113.42",
            "verificar se houve mudança de roteamento para o ASN 15169",
            "quais rotas atuais o RouteBrain conhece para o ASN 15169?",
        ]
    elif "dom" in topic_lower or "youtube" in topic_lower or "." in topic_lower:
        questions = [
            "qual rota para youtube.com",
            "Qual roteamento no sentido de downstream e upstream para o youtube.com?",
            "me ajuda a analisar o domínio youtube.com sem executar medição ativa",
        ]
    elif "baseline" in topic_lower or "traceroute" in topic_lower or "ping" in topic_lower:
        questions = [
            "verifica se o 8.8.8.8 está operacional",
            "existe baseline para o IP 8.8.8.8?",
            "quando posso executar traceroute com confirmação explícita?",
        ]
    else:
        questions = [
            "verifica se o 8.8.8.8 está operacional",
            "qual rota para youtube.com",
            "Me mostra como o ASN 15169 enxerga o IP 203.0.113.42",
        ]
    return {"topic": safe_topic, "questions": questions, "risk": "read_only"}


def explain_question_type(question_type: str) -> dict[str, object]:
    """Explain a safe RouteBrain question type."""
    safe_type = sanitize_user_message_for_agent(question_type)[:120].lower()
    explanations = {
        "ip_operational_check": "Consulta contexto local e evidências salvas sobre um IP público; não executa ping/traceroute automaticamente.",
        "route_to_domain": "Analisa pergunta sobre domínio e pode orientar DNS/rota; medições ativas exigem confirmação explícita.",
        "bgp_asn_ip_visibility": "Consulta como um ASN/IP aparece na base BGP local do RouteBrain; não altera rotas.",
        "asn_route_change_check": "Ajuda a verificar mudança de roteamento de ASN com base em dados salvos e snapshots controlados.",
        "real_access_simulation": "Planeja uma simulação de navegação, mas execução sintética depende do backend e confirmação.",
        "ix_inventory_context": "Consulta contexto de inventário/IX/PTT conhecido; não coleta dados novos.",
    }
    explanation = explanations.get(
        safe_type,
        "Tipo conversacional ou genérico. Posso ajudar a formular uma pergunta com IP, domínio, ASN, BGP, baseline ou destino observado.",
    )
    return {"question_type": safe_type or "general", "explanation": explanation, "risk": "read_only"}


def maybe_get_safe_system_context(include_limits: bool) -> dict[str, object]:
    """Return only fixed, non-sensitive RouteBrain context."""
    payload: dict[str, object] = {"context": build_routebrain_safe_context()}
    if include_limits:
        payload["limits"] = [
            "não inclui .env, credenciais, source address, payloads, query strings ou relatórios brutos",
            "não inclui dados sensíveis da MikroTik",
            "não executa coleta, ping, traceroute, baseline, enrich ou navegação sintética",
        ]
    return payload
