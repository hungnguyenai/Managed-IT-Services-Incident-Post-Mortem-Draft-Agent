"""AgentCore Platform v1.0"""

# Node contract (agents_layer_design.md §1):
#  - Extend FunctionNode; implement execute(state) -> dict (return ONLY changed keys)
#  - Return AgentStatus enum constants — never plain strings [A1]
#  - S-1 trust declared via required_trust_level ClassVar (on-call/IT-ops staff)

from __future__ import annotations

from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import (
    DRAFTED,
    NO_MATCH,
    reconstruct_pir,
    retrieve_context,
)

from shared.utils.audit_logger import emit_trace_event


class MainNode(FunctionNode):
    """ContextRetrieve + RootCauseReconstruct.

    Retrieves system-architecture + prior-incident-history passages (a query may
    match multiple services/components — the cross-service incident case) and
    reconstructs a draft PIR: timeline, root cause with 5-Why, contributing factors,
    customer impact, and corrective actions with ownership suggestions.
    `retrieved_context` is written once here — NON-SUPPRESSIBLE (the citation trail);
    downstream nodes must never filter or empty it.

    The injected kb_client (production) or the deterministic corpus (CI) is used. If
    an injected client (or the deterministic corpus) yields no passages, return a
    `NO_MATCH` disposition and NEVER draft an ungrounded PIR.

    S-1: INTERNAL.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def __init__(self, kb_client: Any = None) -> None:
        super().__init__()
        self._kb_client = kb_client

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("status") in (AgentStatus.ERROR, AgentStatus.ERROR.value):
            return {}

        emit_trace_event("context_retrieve_start", {"node": "MainNode"}, state)

        query = state.get("sanitized_query") or state.get("validated_input") or ""

        try:
            context = retrieve_context(query, kb_client=self._kb_client)
        except Exception as e:  # noqa: BLE001
            emit_trace_event("context_retrieve_error", {"error": str(e)}, state)
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", []) + [f"MainNode: {e}"],
            }

        # Readiness gate: no matched context must never draft an ungrounded PIR —
        # force NO_MATCH rather than an affirmative draft.
        if not context:
            emit_trace_event("no_incident_context_match", {"query_length": len(query)}, state)
            return {
                "disposition": NO_MATCH,
                "retrieved_context": [],
                "kb_version_manifest": [],
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", [])
                + [
                    "MainNode: no_incident_context_match — no system-architecture or "
                    "prior-incident-history passage matched this query; cannot draft a "
                    "PIR without current architecture/incident-history grounding"
                ],
            }

        for p in context:
            emit_trace_event(
                "context_retrieved",
                {"citation": p.get("citation"), "service": p.get("service"), "kb_date": p.get("kb_date")},
                state,
            )

        kb_version_manifest = sorted({f"{p['service']} ({p['kb_date']})" for p in context})
        draft_pir = reconstruct_pir(query, context)

        emit_trace_event(
            "root_cause_reconstruct_complete",
            {"service_count": len(kb_version_manifest), "passage_count": len(context)},
            state,
        )

        return {
            "retrieved_context": context,
            "kb_version_manifest": kb_version_manifest,
            "disposition": DRAFTED,
            "draft_pir": draft_pir,
            "status": AgentStatus.SUCCESS.value,
        }
