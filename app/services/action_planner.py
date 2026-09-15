from __future__ import annotations

from typing import Any

from app.services.agents.schemas import ActionPlan, ActionPlanStep


READ_ONLY_ACTIONS = {
    "resolve_dns",
    "generate_destination_report",
    "show_bgp_route_for_ip",
    "check_asn_in_as_path",
    "generate_asn_ip_visibility_report",
    "show_current_asn_routes",
    "create_asn_route_report",
    "view_traceroute_graph",
}
ACTIVE_ACTIONS = {"trace_route", "trace_route_with_inventory", "measure_baseline"}
STATE_CHANGE_ACTIONS = {"promote_to_baseline", "add_asn_to_monitoring", "generate_current_asn_snapshot"}
SYNTHETIC_ACTIONS = {"discover_real_navigation_targets"}
REPORT_ACTIONS = {"generate_destination_report", "generate_asn_ip_visibility_report", "create_asn_route_report"}
EXTERNAL_ROUTE_ACTIONS = {
    "seed_external_services",
    "ingest_existing_traceroutes",
    "enrich_external_hop",
    "rebuild_service_hop_summary",
}


def _as_bool(value: Any) -> bool:
    return bool(value)


def _clean_text(value: Any, fallback: str = "") -> str:
    text = " ".join(str(value or "").split()).strip()
    return text or fallback


def _action_type(action_id: str | None, raw_type: str | None = None) -> str:
    if raw_type in {"read_only", "active_measurement", "state_change", "synthetic_navigation", "report"}:
        return raw_type
    if action_id in ACTIVE_ACTIONS:
        return "active_measurement"
    if action_id in STATE_CHANGE_ACTIONS:
        return "state_change"
    if action_id in SYNTHETIC_ACTIONS:
        return "synthetic_navigation"
    if action_id in REPORT_ACTIONS:
        return "report"
    if action_id in EXTERNAL_ROUTE_ACTIONS:
        return "read_only"
    return "read_only"


def _risk_for(action_type: str, action_id: str | None, raw_risk: Any = None) -> str:
    text = str(raw_risk or "").lower()
    if action_type == "active_measurement":
        return "medium"
    if action_type in {"state_change", "synthetic_navigation"}:
        return "high"
    if action_type == "report":
        return "low"
    if "high" in text or "state" in text or "synthetic" in text:
        return "high"
    if "active" in text or "measurement" in text or "enrichment" in text:
        return "medium"
    if action_id in READ_ONLY_ACTIONS:
        return "low"
    return "none"


def _endpoint_for(action_id: str | None, request_uid: str | None) -> tuple[str | None, str | None]:
    if not action_id or not request_uid:
        return None, None
    return f"/questions/{request_uid}/actions/{action_id}", "POST"


def normalize_action_plan_step(step: dict[str, Any], *, request_uid: str | None = None, index: int = 1) -> dict[str, Any]:
    known_action_ids = READ_ONLY_ACTIONS | ACTIVE_ACTIONS | STATE_CHANGE_ACTIONS | SYNTHETIC_ACTIONS
    raw_action_id = step.get("action_id")
    if not raw_action_id and step.get("id") in known_action_ids:
        raw_action_id = step.get("id")
    action_id = _clean_text(raw_action_id, "")
    action_type = _action_type(action_id or None, step.get("action_type"))
    requires_confirmation = _as_bool(step.get("requires_confirmation")) or action_type in {
        "active_measurement",
        "state_change",
        "synthetic_navigation",
    }
    requires_admin = _as_bool(step.get("requires_admin")) or action_type in {
        "active_measurement",
        "state_change",
        "synthetic_navigation",
    }
    endpoint = _clean_text(step.get("endpoint"), "") or None
    method = _clean_text(step.get("method"), "") or None
    if not endpoint:
        endpoint, method = _endpoint_for(action_id or None, request_uid)
    if method is None and endpoint:
        method = "POST"
    executable = bool(endpoint and step.get("executable", True))
    status = "planned"
    reason = step.get("reason")
    if executable and requires_admin:
        status = "requires_confirmation" if requires_confirmation else "requires_admin"
    elif executable:
        status = "available"
    elif reason:
        status = "not_available"
    plan_step = ActionPlanStep(
        id=_clean_text(step.get("id"), f"step_{index}"),
        label=_clean_text(step.get("label"), f"Passo {index}"),
        description=_clean_text(step.get("description"), "Passo planejado pelo RouteBrain."),
        action_id=action_id or None,
        action_type=action_type,  # type: ignore[arg-type]
        risk=_risk_for(action_type, action_id or None, step.get("risk")),  # type: ignore[arg-type]
        requires_admin=requires_admin,
        requires_confirmation=requires_confirmation,
        executable=executable,
        endpoint=endpoint,
        method=method,
        params=step.get("params") if isinstance(step.get("params"), dict) else {},
        status=status,  # type: ignore[arg-type]
        reason=_clean_text(reason, "") or None,
    )
    return plan_step.model_dump()


def _recommended_by_id(recommended_actions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for action in recommended_actions:
        if not isinstance(action, dict):
            continue
        action_id = str(action.get("id") or action.get("action") or "").strip()
        if action_id:
            result[action_id] = action
    return result


def _step(
    step_id: str,
    label: str,
    description: str,
    *,
    action_id: str | None = None,
    action_type: str | None = None,
    reason: str | None = None,
    executable: bool = True,
    endpoint: str | None = None,
    method: str | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": step_id,
        "label": label,
        "description": description,
        "action_id": action_id,
        "action_type": action_type or _action_type(action_id),
        "reason": reason,
        "executable": executable,
        "endpoint": endpoint,
        "method": method,
        "params": params or {},
    }


def _merge_recommended_metadata(steps: list[dict[str, Any]], recommended_actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = _recommended_by_id(recommended_actions)
    merged: list[dict[str, Any]] = []
    for step in steps:
        action_id = step.get("action_id")
        action = by_id.get(str(action_id or ""))
        if action:
            step = {
                **step,
                "label": step.get("label") or action.get("label"),
                "description": step.get("description") or action.get("description"),
                "requires_confirmation": action.get("requires_confirmation"),
                "risk": action.get("risk"),
                "executable": bool(action.get("enabled", True)),
                "reason": None if action.get("enabled", True) else action.get("reason") or "Ação planejada, mas ainda não disponível neste contexto.",
            }
        merged.append(step)
    return merged


def _plan_from_steps(
    *,
    title: str,
    summary: str,
    steps: list[dict[str, Any]],
    intent: str | None,
    request_uid: str | None,
    recommended_actions: list[dict[str, Any]],
    evidence_required: list[str],
    generated_by: str = "routebrain_backend",
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    normalized = [
        normalize_action_plan_step(step, request_uid=request_uid, index=index)
        for index, step in enumerate(_merge_recommended_metadata(steps, recommended_actions), start=1)
    ]
    requires_admin = any(step["requires_admin"] for step in normalized)
    requires_confirmation = any(step["requires_confirmation"] for step in normalized)
    active_action_required = any(
        step["action_type"] in {"active_measurement", "state_change", "synthetic_navigation"} for step in normalized
    )
    plan = ActionPlan(
        plan_id=f"{request_uid}:planned" if request_uid else None,
        title=title,
        summary=summary,
        steps=normalized,
        requires_admin=requires_admin,
        requires_confirmation=requires_confirmation,
        active_action_required=active_action_required,
        evidence_required=evidence_required,
        can_execute_now=False,
        generated_by=generated_by,  # type: ignore[arg-type]
        warnings=[
            "Plano sugerido não executa ações automaticamente.",
            "Ações ativas ou alterações continuam exigindo RBAC e confirmação explícita.",
            *(warnings or []),
        ],
    )
    return plan.model_dump()


def build_action_plan_from_recommended_actions(recommended_actions: list[Any], context: dict[str, Any]) -> dict[str, Any]:
    safe_actions = [action for action in recommended_actions if isinstance(action, dict)]
    request_uid = context.get("request_uid")
    steps = [
        _step(
            f"recommended_{index}",
            str(action.get("label") or action.get("id") or action.get("action") or f"Ação {index}"),
            str(action.get("description") or "Ação recomendada pelo RouteBrain."),
            action_id=str(action.get("id") or action.get("action") or "") or None,
        )
        for index, action in enumerate(safe_actions, start=1)
    ]
    return _plan_from_steps(
        title="Plano sugerido a partir das ações disponíveis",
        summary="Sequência planejada com as ações já expostas pelo backend RouteBrain.",
        steps=steps,
        intent=context.get("intent"),
        request_uid=str(request_uid) if request_uid else None,
        recommended_actions=safe_actions,
        evidence_required=["routebrain_backend"],
    )


def build_conversational_action_plan(question: str, agent_result: dict[str, Any]) -> dict[str, Any] | None:
    intent = str(agent_result.get("intent") or "").strip()
    if intent == "general_greeting":
        return None
    suggested_questions = []
    assistant = agent_result.get("llm_assistant") if isinstance(agent_result.get("llm_assistant"), dict) else {}
    for item in assistant.get("suggested_questions") or []:
        text = _clean_text(item)
        if text:
            suggested_questions.append(text)
        if len(suggested_questions) >= 3:
            break
    steps = [
        _step(
            "choose_question",
            "Escolher uma pergunta operacional",
            "Escolha um exemplo ou formule uma pergunta com IP, domínio ou ASN para o RouteBrain buscar evidência local.",
            action_type="read_only",
            executable=False,
        )
    ]
    for index, suggested in enumerate(suggested_questions, start=1):
        steps.append(
            _step(
                f"example_{index}",
                f"Exemplo {index}",
                suggested,
                action_type="read_only",
                executable=False,
            )
        )
    return _plan_from_steps(
        title="Plano simples para começar",
        summary="Esta resposta é orientação conversacional. Nenhuma investigação operacional foi iniciada.",
        steps=steps,
        intent=intent,
        request_uid=None,
        recommended_actions=[],
        evidence_required=[],
        generated_by="agent" if (agent_result.get("agent_observability") or {}).get("used_agent") else "routebrain_backend",
    )


def build_action_plan_for_question(question_payload: dict[str, Any]) -> dict[str, Any] | None:
    intent = str(question_payload.get("intent") or question_payload.get("operational_intent") or "").strip()
    recommended_actions = [
        action for action in (question_payload.get("recommended_actions") or []) if isinstance(action, dict)
    ]
    request_uid = str(question_payload.get("request_uid") or "").strip() or None
    target = question_payload.get("target_context") if isinstance(question_payload.get("target_context"), dict) else {}
    target_label = target.get("target_domain") or target.get("target_ip") or target.get("target_prefix") or target.get("target_label") or "destino informado"

    if intent in {"general_greeting", "general_test", "help_prompt", "conversational_help", "safety_blocked"}:
        return build_conversational_action_plan(str(question_payload.get("question") or ""), question_payload)

    if intent in {"ip_operational_check", "route_to_ip"}:
        steps = [
            _step("inventory_lookup", "Verificar inventário de host", "Cruzar o IP/hop com inventory_hosts e candidatos já descobertos.", action_type="read_only", executable=False),
            _step("destination_report", "Consultar relatório do destino", f"Consolidar evidências já salvas para {target_label}.", action_id="generate_destination_report", action_type="report"),
            _step("bgp_local", "Verificar BGP local", "Consultar prefixo, origem, peers e limitações na base local do RouteBrain.", action_id="show_bgp_route_for_ip"),
            _step("observed_destination", "Consultar observed destinations", "Verificar se o IP aparece nas observações já salvas da MikroTik, sem coletar agora.", action_type="read_only", executable=False),
            _step("inventory_discovery", "Planejar descoberta read-only de inventário", "Se o host interno ainda for desconhecido, operador/admin pode rodar discovery MikroTik read-only e revisar candidatos.", action_type="read_only", executable=False),
            _step("promote_candidate", "Promover candidato se confirmado", "Candidato só vira inventory_host com operador/admin, confirm=true e revisão da evidência.", action_type="state_change", executable=False),
            _step("baseline", "Verificar baseline", "Checar baseline e medições salvas antes de sugerir medição ativa.", action_type="read_only", executable=False),
            _step("measure_if_confirmed", "Medir baseline/traceroute se confirmado", "Se faltar evidência atual, operador/admin pode executar ping/traceroute pelo backend com confirmação explícita.", action_id="measure_baseline", action_type="active_measurement"),
            _step("final_report", "Gerar relatório consolidado", "Apresentar conclusão com evidências, lacunas e próximos passos.", action_id="generate_destination_report", action_type="report"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para investigar o IP",
            summary="Plano read-only primeiro; qualquer medição ativa fica condicionada a RBAC e confirmação.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["inventory", "inventory_candidates", "bgp_local", "observed_destinations", "baseline", "saved_measurements"],
        )

    if intent in {"route_to_domain", "domain_analysis", "domain_operational_check"}:
        steps = [
            _step("dns", "Resolver DNS", f"Resolver os IPs públicos atuais de {target_label}.", action_id="resolve_dns"),
            _step("public_ips", "Verificar IPs públicos", "Filtrar alvos privados/reservados antes de qualquer medição.", action_type="read_only", executable=False),
            _step("bgp_local", "Verificar BGP local", "Consultar cobertura BGP local dos IPs resolvidos.", action_id="show_bgp_route_for_ip"),
            _step("observed_destinations", "Consultar observed destinations", "Checar observações já salvas para os IPs/domínio.", action_type="read_only", executable=False),
            _step("inventory_hops", "Cruzar hops internos com inventário", "Quando houver medições salvas, identificar hops conhecidos, candidatos ou desconhecidos.", action_type="read_only", executable=False),
            _step("inventory_discovery", "Planejar descoberta read-only de inventário", "Se aparecer hop interno desconhecido, sugerir discovery MikroTik read-only para operador/admin revisar.", action_type="read_only", executable=False),
            _step("traceroute_confirmed", "Traceroute com confirmação", "Executar traceroute/ping somente se operador/admin confirmar no backend.", action_id="trace_route", action_type="active_measurement"),
            _step("report", "Gerar relatório", "Consolidar DNS, BGP, observações, medições salvas e lacunas.", action_id="generate_destination_report", action_type="report"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para investigar o domínio",
            summary="O plano resolve e cruza evidências locais antes de qualquer medição ativa confirmada.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["dns", "inventory", "inventory_candidates", "bgp_local", "observed_destinations", "saved_measurements"],
        )

    if intent == "bgp_asn_ip_visibility":
        steps = [
            _step("inventory_lookup", "Verificar inventário local", "Cruzar o IP com hosts confirmados e candidatos antes de concluir impacto interno.", action_type="read_only", executable=False),
            _step("bgp_route", "Verificar rota BGP do IP", "Consultar prefixo, origem e peers observados localmente.", action_id="show_bgp_route_for_ip"),
            _step("as_path", "Verificar ASN no AS_PATH", "Checar se o ASN consultado aparece nos caminhos observados, quando houver dados.", action_id="check_asn_in_as_path"),
            _step("asn_ip_report", "Gerar relatório ASN/IP", "Consolidar visibilidade, limitações e evidência BGP local.", action_id="generate_asn_ip_visibility_report", action_type="report"),
            _step("optional_monitoring", "Monitoramento opcional do ASN", "Adicionar ASN ao monitoramento só se operador/admin confirmar.", action_id="add_asn_to_monitoring", action_type="state_change"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para visibilidade ASN/IP",
            summary="Plano usa evidência BGP local e deixa monitoramento como alteração opcional confirmada.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["inventory", "bgp_local", "as_path_samples"],
        )

    if intent in {"asn_route_change_check", "asn_route_monitoring_request"}:
        steps = [
            _step("baseline_check", "Verificar baseline existente", "Checar se o ASN já tem baseline histórico suficiente.", action_id="show_current_asn_routes"),
            _step("snapshot_if_confirmed", "Gerar snapshot atual se confirmado", "Registrar visão atual apenas com confirmação de operador/admin.", action_id="generate_current_asn_snapshot", action_type="state_change"),
            _step("compare_baseline", "Comparar baseline", "Comparar estado atual e baseline disponível sem alterar BGP bruto.", action_type="read_only", executable=False),
            _step("route_report", "Gerar relatório de mudança", "Consolidar variações, limitações e confiança.", action_id="create_asn_route_report", action_type="report"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para mudança de rota ASN",
            summary="Plano prioriza baseline existente; snapshots novos exigem confirmação e auditoria.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["asn_baseline", "current_routes"],
        )

    if intent in {"real_access_simulation", "synthetic_navigation_discovery"}:
        steps = [
            _step("explain_synthetic", "Explicar necessidade de navegação sintética", "Acesso real exige automação controlada para descobrir destinos efetivos.", action_type="read_only", executable=False),
            _step("discover_targets", "Descobrir destinos reais via DevTools", "Planejar execução pelo backend se o executor estiver conectado e operador/admin confirmar.", action_id="discover_real_navigation_targets", action_type="synthetic_navigation"),
            _step("dns_after_discovery", "Resolver DNS dos destinos descobertos", "Depois da descoberta, resolver DNS dos domínios encontrados.", action_id="resolve_dns"),
            _step("inventory_hops", "Cruzar hops internos com inventário", "Após evidência salva, identificar hosts confirmados, candidatos ou desconhecidos no caminho interno.", action_type="read_only", executable=False),
            _step("report", "Gerar relatório", "Consolidar destinos reais, DNS, BGP e lacunas.", action_id="generate_destination_report", action_type="report"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para simulação de acesso real",
            summary="A navegação sintética fica apenas planejada até confirmação explícita e executor disponível.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["synthetic_navigation_outputs", "dns", "inventory", "inventory_candidates", "bgp_local"],
            warnings=["Nenhuma navegação sintética é executada ao gerar este plano."],
        )

    if intent in {
        "external_route_inventory_query",
        "service_route_hops_query",
        "service_route_compare",
        "unknown_external_hops_query",
        "ptt_route_context_query",
    }:
        service_slug = str(target.get("service") or target.get("subject_service") or "").strip().lower()
        if intent in {"external_route_inventory_query", "service_route_hops_query"} and service_slug:
            steps = [
                _step(
                    "select_real_target",
                    "Selecionar alvo real",
                    "Backend RouteBrain escolhe target ativo, observed destination relacionado ou seed DNS seguro antes de medir.",
                    action_type="read_only",
                    executable=False,
                ),
                _step(
                    "trace_service_route",
                    "Mapear rota",
                    "Executar traceroute controlado com admin + confirmação e ingerir o resultado automaticamente no inventário externo.",
                    action_id="trace_external_route_service",
                    action_type="active_measurement",
                    endpoint=f"/external-routes/services/{service_slug}/trace",
                    method="POST",
                    params={"confirm": True, "target_override": None, "max_hops": 20, "service": service_slug},
                ),
                _step(
                    "ingest_external_hops",
                    "Ingerir hops",
                    "Persistir hops externos no inventário, com private/reserved classificados como private/inferred_from_path.",
                    action_type="read_only",
                    executable=False,
                ),
                _step(
                    "create_edges",
                    "Criar edges",
                    "Gerar edges entre hops consecutivos com transições classificadas e auditoria sanitizada.",
                    action_type="read_only",
                    executable=False,
                ),
                _step(
                    "enrich_hops",
                    "Enriquecer hops",
                    "Enriquecer apenas os hops públicos permitidos com BGP local e fallback externo já autorizado.",
                    action_type="read_only",
                    executable=False,
                ),
                _step(
                    "generate_report",
                    "Gerar relatório",
                    "Consolidar run_uid, target, hops, edges, unknowns e link do grafo disponível.",
                    action_type="report",
                    executable=False,
                ),
            ]
            return _plan_from_steps(
                title="Plano sugerido para mapear rota externa",
                summary="Plano planeja a execução controlada no backend RouteBrain; apenas o passo de trace é acionável e exige admin + confirmação.",
                steps=steps,
                intent=intent,
                request_uid=request_uid,
                recommended_actions=recommended_actions,
                evidence_required=["external_route_inventory", "saved_traceroutes", "external_enrichment"],
                warnings=[
                    "O backend escolhe o alvo real antes da execução.",
                    "Nenhuma medição nova é feita sem admin + confirm=true.",
                ],
            )
        steps = [
            _step("service_inventory", "Consultar inventário externo", "Listar serviços, hops, ASNs e observações já salvas para rotas externas.", action_type="read_only", executable=False),
            _step("unknown_hops", "Separar hops desconhecidos", "Destacar hops externos ainda sem enriquecimento seguro.", action_type="read_only", executable=False),
            _step("compare_routes", "Comparar serviços", "Cruzar hops e ASNs entre dois serviços quando a pergunta pedir comparação.", action_type="read_only", executable=False),
            _step("refresh_summary", "Rebuild do resumo", "Reagregar o resumo por serviço depois de ingestão ou enrichment read-only.", action_id="rebuild_service_hop_summary", action_type="read_only"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para inventário de rotas externas",
            summary="Plano read-only sobre serviços externos, hops, ASNs e PTT/IX; não executa traceroute novo automaticamente.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["external_route_inventory", "saved_traceroutes", "external_enrichment"],
            warnings=["Se não houver dados, é preciso ingerir traceroutes já existentes ou medir traceroute explicitamente, sem execução automática."],
        )

    if intent in {"ix_inventory_context", "inventory_query"}:
        steps = [
            _step("local_inventory", "Consultar inventário local", "Buscar hosts e contexto já cadastrados no RouteBrain.", action_type="read_only", executable=False),
            _step("host_candidates", "Consultar candidatos de hosts", "Separar candidatos ainda não promovidos de hosts confirmados.", action_type="read_only", executable=False),
            _step("inventory_discovery", "Planejar discovery read-only", "Operador/admin pode executar discovery MikroTik read-only para alimentar candidatos, sem promoção automática.", action_type="read_only", executable=False),
            _step("ixbr_context", "Consultar contexto público IX.br", "Cruzar com dados públicos IX.br quando disponível.", action_type="read_only", executable=False),
            _step("inventory_report", "Gerar relatório", "Consolidar inventário, contexto público e lacunas.", action_id="generate_destination_report", action_type="report"),
        ]
        return _plan_from_steps(
            title="Plano sugerido para inventário/IX.br",
            summary="Plano apenas read-only; não promove traceroute nem altera inventário automaticamente.",
            steps=steps,
            intent=intent,
            request_uid=request_uid,
            recommended_actions=recommended_actions,
            evidence_required=["inventory", "inventory_candidates", "ixbr_public_context"],
        )

    if recommended_actions:
        return build_action_plan_from_recommended_actions(recommended_actions, question_payload)
    return None
