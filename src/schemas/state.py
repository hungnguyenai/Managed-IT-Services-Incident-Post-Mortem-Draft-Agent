"""AgentCore Platform v1.0"""

# ADR-005: State must be a flat TypedDict (see ADR-005 for the prohibited alternatives).
# LangGraph checkpoints use msgpack serialization; non-flat objects cause silent
# corruption. Extend AgentState with agent-specific fields only. Do NOT add
# credentials, secrets, or other non-flat objects.

from typing import Optional

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """State for SVC-C2-101 Managed IT Services Incident Post-Mortem Draft Agent
    (VectorRAG node-backbone).

    Inherited fields from AgentState (do not re-declare):
      user_input, status, session_id, node_history, error_log,
      validated_input, hitl_*, trace_id, correlation_id, schema_version,
      response_metadata, trust_level, formatted_output, result

    Incident ticket data + alert-log summary + resolution notes arrive as user_input.
    All fields below are flat, msgpack-safe primitives (ADR-005) — no credentials, no
    connection strings. Only architecture/incident-history citations + snippets are
    retained; no live secrets or internal-only identifiers are ever part of this
    agent's domain (they are screened out at pre_process before retrieval).
    """

    # ── pre_process outputs (InputValidate + CredentialSecretScreen) ─────
    sanitized_query: Optional[str]
    # True when the input was rejected because it carried a live credential/secret
    # or an internal-only host/IP identifier (S-2 domain gate).
    input_screen_flagged: Optional[bool]

    # ── main outputs (ContextRetrieve + RootCauseReconstruct) ────────────
    # Retrieved passages: {citation, service, kb_date, snippet}. NON-SUPPRESSIBLE
    # citation trail — downstream nodes must never empty it (a PIR draft must stay
    # grounded in the architecture/incident-history basis it cites).
    retrieved_context: Optional[list[dict[str, str | int | float | bool | None]]]
    # Versioned KB manifest — one entry per service/component cited (S-4 audit).
    kb_version_manifest: Optional[list[str]]
    # DRAFTED | NO_MATCH — NO_MATCH forces a "no current architecture/incident-history
    # basis found" reply, never an affirmative PIR without grounding.
    disposition: Optional[str]
    # Draft PIR (pre-S-3) — timeline + 5-Why root cause + contributing factors +
    # customer impact + corrective actions.
    draft_pir: Optional[str]

    # ── post_process outputs (PIRAssemble + OutputValidate S-3 + IncidentAudit S-4) ─
    validated_pir: Optional[str]  # final PIR draft incl. non-suppressible review note
    citation_count: Optional[int]  # number of distinct architecture/incident citations
