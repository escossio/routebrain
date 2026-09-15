from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class SuggestedQuestion(BaseModel):
    label: str
    question: str
    risk: str = "read_only"


class SuggestedActionPlanStep(BaseModel):
    label: str
    description: str


class SuggestedActionPlan(BaseModel):
    title: str
    summary: str
    steps: list[SuggestedActionPlanStep] = Field(default_factory=list)


class ConversationAgentStructuredOutput(BaseModel):
    answer: str
    suggested_questions: list[str] = Field(default_factory=list)
    intent_hint: str | None = None
    safety_notes: list[str] = Field(default_factory=list)
    suggested_action_plan: SuggestedActionPlan | None = None


class ActionPlanStep(BaseModel):
    id: str
    label: str
    description: str
    action_id: str | None = None
    action_type: Literal["read_only", "active_measurement", "state_change", "synthetic_navigation", "report"] = "read_only"
    risk: Literal["none", "low", "medium", "high"] = "low"
    requires_admin: bool = False
    requires_confirmation: bool = False
    executable: bool = False
    endpoint: str | None = None
    method: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    status: Literal["planned", "available", "requires_confirmation", "requires_admin", "not_available"] = "planned"
    reason: str | None = None


class ActionPlan(BaseModel):
    plan_id: str | None = None
    title: str
    summary: str
    status: Literal["planned"] = "planned"
    steps: list[ActionPlanStep] = Field(default_factory=list)
    requires_admin: bool = False
    requires_confirmation: bool = False
    active_action_required: bool = False
    evidence_required: list[str] = Field(default_factory=list)
    can_execute_now: bool = False
    execution_owner: Literal["routebrain_backend"] = "routebrain_backend"
    generated_by: Literal["agent", "routebrain_backend"] = "routebrain_backend"
    warnings: list[str] = Field(default_factory=list)


class AgentObservability(BaseModel):
    enabled: bool = False
    used_agent: bool = False
    provider: str | None = None
    model: str | None = None
    primary_agent: str | None = None
    final_agent: str | None = None
    handoffs: list[str] = Field(default_factory=list)
    tools_called: list[str] = Field(default_factory=list)
    guardrails_triggered: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    response_type: Literal[
        "conversational_guidance",
        "operational_evidence",
        "local_utility",
        "local_operational",
    ] = "conversational_guidance"
    active_action_executed: bool = False
    evidence_source: Literal["agent", "routebrain_backend", "local_utility", "fallback"] = "fallback"
    trace_available: bool = False
    trace_id: str | None = None
    trace_safe_summary: dict = Field(default_factory=dict)


class ConversationAgentResult(BaseModel):
    answer: str
    suggested_questions: list[str] = Field(default_factory=list)
    intent_hint: str | None = None
    safety_notes: list[str] = Field(default_factory=list)
    used_llm: bool = False
    provider: str
    model: str | None = None
    fallback: bool = True
    error: str | None = None
    agent_observability: AgentObservability | None = None
    suggested_action_plan: dict[str, Any] | None = None
