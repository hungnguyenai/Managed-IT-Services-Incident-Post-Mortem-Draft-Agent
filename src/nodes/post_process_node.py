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

from shared.utils.audit_logger import emit_trace_event

# Credential-like patterns rejected in output (additive to the default scan) — a
# leaked secret from the ingested logs must never survive into the PIR draft.
_SENSITIVE_PATTERNS = (
    "bearer ",
    "authorization:",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "connection_string",
    "conn_str",
    "private_key",
)

# Unsupported certainty phrasing a PIR draft must NOT assert. A post-incident review
# is a working draft for the on-call engineer, never a guarantee of prevention.
_OVERCLAIM_PATTERNS = (
    "guaranteed to prevent recurrence",
    "root cause is 100% certain",
    "this will never happen again",
    "no further action required",
    "we certify this incident will not recur",
)

# Structural completeness check — a PIR draft MUST retain all required sections.
_REQUIRED_SECTIONS = ("Timeline", "5-Why", "Contributing Factors", "Corrective Action")

# ResponseValidate — a drafted PIR MUST retain an architecture/incident-history
# citation marker so it stays grounded in the passages it cites (no unsupported
# root-cause claims).
_CITATION_MARKERS = ("ARCH-PAYGW-", "ARCH-AUTHIAM-", "ARCH-DBCLUSTER-", "ARCH-NETEDGE-", "KB version")

# The non-suppressible review-status note appended to every drafted PIR.
_REVIEW_NOTE = (
    "\n\n---\n**This is a draft PIR pending on-call engineer review, not a final report.** "
    "Verify timeline, root cause, and corrective-action ownership before SLA submission "
    "(48-72h reporting deadline)."
)

# Sentinel used when disposition is NO_MATCH (no grounding to check).
_NO_MATCH_SENTINEL = "no_incident_context_match"

# Rendered when there is no draft_pir to validate (e.g. main_node never ran, or was
# invoked directly with a degenerate state). The grounding + structural checks below
# are skipped for this sentinel — there is nothing to cite or validate.
_NO_ANSWER_SENTINEL = "No PIR draft synthesized"


class PostProcessNode(FunctionNode):
    """PIRAssemble (OutputValidate S-3) + IncidentAudit (S-4).

    Responsibilities:
    - Append the non-suppressible "draft — pending review" note to every drafted PIR.
    - S-3: block credential-like patterns leaking from the ingested logs; block
      unsupported prevention-guarantee phrasing; structural check (timeline + 5-Why +
      contributing factors + corrective actions all present); ResponseValidate rejects
      a draft that carries no architecture/incident-history citation (grounding
      requirement).
    - S-4: emit_trace_event audit record — disposition, KB version manifest, citation
      count; no credentials/PII/internal identifiers.

    S-1: INTERNAL.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("status") in (AgentStatus.ERROR, AgentStatus.ERROR.value):
            return {}

        emit_trace_event("output_validate_start", {"node": "PostProcessNode"}, state)

        draft_pir = state.get("draft_pir") or ""
        context = state.get("retrieved_context") or []
        kb_version_manifest = state.get("kb_version_manifest") or []
        disposition = state.get("disposition") or _NO_MATCH_SENTINEL

        body = draft_pir if draft_pir.strip() else _NO_ANSWER_SENTINEL
        validated_pir = body + _REVIEW_NOTE
        citation_count = len({p.get("citation") for p in context if p.get("citation")})

        emit_trace_event(
            "incident_audit",
            {
                "disposition": disposition,
                "kb_version_manifest": kb_version_manifest,
                "citation_count": citation_count,
            },
            state,
        )

        return {
            "validated_pir": validated_pir,
            "citation_count": citation_count,
            "formatted_output": validated_pir,
            "result": validated_pir,
            "status": AgentStatus.SUCCESS.value,
        }

    # ── S-3 output gate ────────────────────────────────────────────────────

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 domain hook (runs after the default credential scan).

        Contract (FunctionNode 1.0.0): receive the execute() result dict, RETURN it;
        MAY raise to block output.
        - Block credential-like patterns / connection strings leaking from logs.
        - Block unsupported prevention-guarantee/certainty assertions.
        - Structural completeness: Timeline + 5-Why + Contributing Factors +
          Corrective Actions must all be present.
        - ResponseValidate: a drafted PIR MUST retain an architecture/incident-history
          citation marker (grounding requirement — no unsupported root-cause claims).
        """
        for key, value in result.items():
            if not isinstance(value, str):
                continue
            lowered = value.lower()
            for pattern in _SENSITIVE_PATTERNS:
                if pattern in lowered:
                    raise RuntimeError(f"PostProcessNode S-3: sensitive pattern '{pattern}' in result['{key}']")
            for pattern in _OVERCLAIM_PATTERNS:
                if pattern in lowered:
                    raise RuntimeError(
                        f"PostProcessNode S-3: unsupported prevention-guarantee phrasing '{pattern}' in result['{key}']"
                    )

        pir = result.get("validated_pir")
        if isinstance(pir, str) and pir.strip() and _NO_ANSWER_SENTINEL not in pir:
            missing = [s for s in _REQUIRED_SECTIONS if s not in pir]
            if missing:
                raise RuntimeError(
                    f"PostProcessNode S-3 structural check: PIR draft missing required section(s) {missing}"
                )
            if not any(marker in pir for marker in _CITATION_MARKERS):
                raise RuntimeError(
                    "PostProcessNode S-3 ResponseValidate: PIR draft carries no "
                    "architecture/incident-history citation — blocking unsupported "
                    "root-cause claim"
                )
        return result
