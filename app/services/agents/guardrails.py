from __future__ import annotations

import re


_EXPLICIT_SECRET_RE = re.compile(
    r"(?i)(minha\s+senha\s+(?:e|é)|openai_api_key\s*=|authorization\s*:\s*bearer|"
    r"\bsk-[A-Za-z0-9_-]{12,}\b|api[_-]?key\s*=|token\s*=|senha\s*=|password\s*=|"
    r"client_secret\s*=|access_token\s*=|refresh_token\s*=|cookie\s*:|set-cookie\s*:|x-api-key\s*:)"
)
_ACTIVE_ACTION_RE = re.compile(
    r"(?i)\b("
    r"ping|traceroute|trace\s*route|baseline|enrich|devtools|navega(r|ção)?|simula(r)?|"
    r"mikrotik|promove(r)?|altera(r)?|muda(r)?|aplica(r)?|confirma(r)?|coleta(r)?|"
    r"medi[çc][aã]o|medir|medida ativa"
    r")\b"
)
_ACTIVE_ACTION_VERB_RE = re.compile(
    r"(?i)\b("
    r"execut(a|e|ar)|rod(a|e|ar)|inicia(r)?|dispara(r)?|coleta(r)?|"
    r"ping|traceroute|trace\s*route|baseline|enrich|devtools|navega(r|ção)?|simula(r)?|"
    r"mikrotik|promove(r)?|altera(r)?|muda(r)?|aplica(r)?|confirma(r)?"
    r")\b"
)
_ACTION_REQUEST_RE = re.compile(
    r"(?i)\b("
    r"execute|executa|executar|rode|roda|rodar|faça|faca|fazer|inicie|inicia|"
    r"colete|coleta|coletar|dispare|dispara|promova|promove|promover|altere|altera|alterar"
    r")\b"
)

_FORBIDDEN_OUTPUT_REPLACEMENTS = {
    "executei o ping": "Posso orientar essa ação, mas a execução depende do RouteBrain com permissão e confirmação explícita.",
    "executei traceroute": "Posso orientar essa ação, mas a execução depende do RouteBrain com permissão e confirmação explícita.",
    "coletei da MikroTik": "Posso orientar essa ação, mas a execução depende do RouteBrain com permissão e confirmação explícita.",
    "coletei da Mikrotik": "Posso orientar essa ação, mas a execução depende do RouteBrain com permissão e confirmação explícita.",
    "alterei baseline": "Posso orientar essa ação, mas a execução depende do RouteBrain com permissão e confirmação explícita.",
}
_OPERATIONAL_CERTAINTY_RE = re.compile(
    r"(?i)\b("
    r"o\s+destino\s+est[aá]\s+operacional|o\s+ip\s+est[aá]\s+operacional|"
    r"a\s+rota\s+est[aá]\s+normal|a\s+rota\s+est[aá]\s+correta|"
    r"houve\s+mudan[çc]a\s+de\s+rota|n[aã]o\s+houve\s+mudan[çc]a\s+de\s+rota|"
    r"o\s+asn\s+enxerga\s+o\s+ip|o\s+asn\s+n[aã]o\s+enxerga\s+o\s+ip|"
    r"ping\s+ok|traceroute\s+ok|baseline\s+alterad[ao]"
    r")\b"
)
_SENSITIVE_OUTPUT_RE = re.compile(
    r"(?i)(\bsk-[A-Za-z0-9_-]{12,}\b|authorization\s*:\s*bearer\s+\S+|"
    r"(password|passwd|senha|token|api[_-]?key|openai_api_key|client_secret|access_token|refresh_token)\s*[:=]\s*['\"]?[^'\"\s]+)"
)

_ACTION_FALLBACK = (
    "Posso orientar essa ação, mas a execução depende do backend RouteBrain com RBAC, permissão e confirmação explícita. "
    "Eu não executo coleta, ping, traceroute, baseline, enrich, DevTools ou navegação sintética."
)


def preflight_agent_input(question: str) -> tuple[bool, str | None]:
    text = str(question or "")
    if _EXPLICIT_SECRET_RE.search(text):
        return (
            False,
            "Não envie senhas, tokens ou chaves para o assistente. Posso ajudar com orientação geral de RouteBrain sem receber segredo.",
        )
    if _ACTIVE_ACTION_VERB_RE.search(text) and _ACTIVE_ACTION_RE.search(text):
        return (False, _ACTION_FALLBACK)
    return True, None


def postflight_agent_output(answer: str) -> str:
    cleaned = str(answer or "")
    cleaned = _SENSITIVE_OUTPUT_RE.sub("[redigido]", cleaned)
    for forbidden, replacement in _FORBIDDEN_OUTPUT_REPLACEMENTS.items():
        cleaned = re.sub(re.escape(forbidden), replacement, cleaned, flags=re.IGNORECASE)
    if _OPERATIONAL_CERTAINTY_RE.search(cleaned):
        cleaned = _OPERATIONAL_CERTAINTY_RE.sub(
            "Sem evidência operacional do backend RouteBrain, não posso afirmar esse resultado",
            cleaned,
        )
    return cleaned


def sanitize_agent_safety_notes(notes: list[str]) -> list[str]:
    cleaned: list[str] = []
    for note in notes:
        text = postflight_agent_output(str(note or ""))
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def sanitize_agent_suggested_questions(questions: list[str]) -> list[str]:
    cleaned: list[str] = []
    for question in questions:
        text = postflight_agent_output(str(question or ""))
        if not text:
            continue
        if _EXPLICIT_SECRET_RE.search(text):
            continue
        if _ACTIVE_ACTION_VERB_RE.search(text) and _ACTIVE_ACTION_RE.search(text):
            text = "Como formular essa ação para passar por RBAC e confirmação explícita no RouteBrain?"
        if text not in cleaned:
            cleaned.append(text)
    return cleaned


def requires_uncertainty_note(answer: str, safety_notes: list[str]) -> bool:
    text = " ".join([str(answer or ""), " ".join(safety_notes)]).lower()
    uncertainty_terms = (
        "não posso afirmar",
        "nao posso afirmar",
        "sem evidência",
        "sem evidencia",
        "depende do backend",
        "exige confirmação",
        "exige confirmacao",
        "não executei",
        "nao executei",
    )
    return not any(term in text for term in uncertainty_terms)
