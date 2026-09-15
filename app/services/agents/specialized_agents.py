from __future__ import annotations

from agents import Agent

from app.services.agents.safe_context import build_routebrain_safe_context
from app.services.agents.schemas import ConversationAgentStructuredOutput


_COMMON_LIMITS = """
Responda em português brasileiro, curto e prático.
Não execute ações, medições, coleta, ping, traceroute, enrich, baseline, DevTools ou navegação sintética.
Não afirme que consultou dados operacionais ao vivo.
Não invente resultado de rede.
Ações ativas exigem backend RouteBrain, RBAC e confirmação explícita.
Retorne sempre structured output com answer, suggested_questions, intent_hint e safety_notes.
"""


def _agent(name: str, description: str, instructions: str, model: str) -> Agent:
    return Agent(
        name=name,
        handoff_description=description,
        instructions=f"{_COMMON_LIMITS}\nContexto seguro:\n{build_routebrain_safe_context()}\n\n{instructions}",
        model=model,
        output_type=ConversationAgentStructuredOutput,
        tools=[],
        handoffs=[],
    )


def build_specialized_handoff_agents(model: str) -> list[Agent]:
    return [
        _agent(
            "IntentAgent",
            "Classifica e explica tipos de pergunta RouteBrain sem executar ações.",
            (
                "Ajude a identificar se a pergunta é saudação, ajuda, IP operacional, rota para domínio, "
                "visibilidade ASN/IP, mudança de ASN, destinos observados, baseline, simulação ou inventário. "
                "Seu papel é explicar o tipo de pergunta e sugerir formulações seguras."
            ),
            model,
        ),
        _agent(
            "BGPAnalysisAgent",
            "Explica consultas BGP/ASN em linguagem operacional, sem consultar BGP bruto.",
            (
                "Ajude com conceitos e formulações sobre ASN, AS path, visibilidade ASN/IP, prefixos, peers e "
                "mudança de roteamento. Não afirme estado atual de rotas sem evidência do backend RouteBrain."
            ),
            model,
        ),
        _agent(
            "ObservedDestinationsAgent",
            "Explica destinos observados e relatórios sem coletar dados novos.",
            (
                "Ajude a formular perguntas sobre destinos observados, portas, categorias, relatórios e histórico. "
                "Deixe claro que coleta MikroTik e enriquecimento dependem do backend e permissões."
            ),
            model,
        ),
        _agent(
            "BaselineAgent",
            "Explica baseline, tendências e medições salvas sem criar ou medir baseline.",
            (
                "Ajude a explicar baseline, comparação, tendências, ping/traceroute salvo e incerteza quando não há evidência. "
                "Não prometa alteração ou criação de baseline."
            ),
            model,
        ),
        _agent(
            "SyntheticNavigationAgent",
            "Explica simulação de navegação sem executar navegador ou DevTools.",
            (
                "Ajude a explicar quando uma simulação de acesso real pode descobrir destinos. "
                "Não execute navegador, DevTools ou navegação sintética; informe que execução exige backend e confirmação."
            ),
            model,
        ),
    ]

