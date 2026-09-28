"""AgentCore Platform v1.0"""

# Node contract (agents_layer_design.md §1):
#  - Extend FunctionNode; implement execute(state) -> dict (return ONLY changed keys)
#  - Return AgentStatus enum constants — never plain strings [A1]
#  - S-1 trust declared via required_trust_level ClassVar (on-call/IT-ops staff)

from __future__ import annotations

import re
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import has_leaked_secret_or_internal_identifier

from shared.utils.audit_logger import emit_trace_event

# Maximum allowed request length (characters)
_MAX_INPUT_LEN = 10_000

_WS = re.compile(r"\s+")


class PreProcessNode(FunctionNode):
    """InputValidate + CredentialSecretScreen — sanitise and screen the ingested
    incident ticket data / alert-log summary / resolution notes.

    Responsibilities:
    - Reject empty / oversized input
    - S-2 deterministic scan (CredentialSecretScreen): reject a live credential/
      secret (Bearer token / connection string / API key / private key) or an
      internal-only host/IP identifier ingested from the logs (regex/pattern, NOT an
      LLM check) — the on-call engineer must redact the excerpt before a PIR draft can
      be produced from it. This runs BEFORE retrieval.
    - Normalise whitespace
    - Emit S-4 trace events: input_validated, secret_or_internal_rejected

    Authorized on-call / IT-ops engineers are internal callers — S-1: INTERNAL.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.INTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        emit_trace_event("input_validate_start", {"node": "PreProcessNode"}, state)

        user_input = state.get("user_input", "") or ""

        if not user_input.strip():
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", []) + ["PreProcessNode: user_input is empty or missing"],
            }

        if len(user_input) > _MAX_INPUT_LEN:
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", [])
                + [f"PreProcessNode: user_input exceeds {_MAX_INPUT_LEN} character limit"],
            }

        if has_leaked_secret_or_internal_identifier(user_input):
            emit_trace_event(
                "secret_or_internal_rejected",
                {"reason": "credential_secret_or_internal_identifier_in_log"},
                state,
            )
            return {
                "input_screen_flagged": True,
                "status": AgentStatus.ERROR.value,
                "error_log": state.get("error_log", [])
                + [
                    "PreProcessNode: CredentialSecretScreen rejected input carrying a "
                    "live credential/secret or an internal-only host/IP identifier — "
                    "redact the log excerpt before resubmitting"
                ],
            }

        sanitized = _WS.sub(" ", user_input).strip()

        emit_trace_event(
            "input_validated",
            {"input_length": len(sanitized)},
            state,
        )

        return {
            "sanitized_query": sanitized,
            "input_screen_flagged": False,
            "validated_input": sanitized,
            "status": AgentStatus.SUCCESS.value,
        }

    def _extra_security_gate_input(self, state: dict[str, Any]) -> dict[str, Any]:
        """S-2 domain hook (runs after the default PII scan).

        Contract (FunctionNode 1.0.0): receive state, RETURN state, never raise —
        reject by setting status=ERROR + appending error_log.
        """
        user_input = state.get("user_input", "") or ""
        if len(user_input) > _MAX_INPUT_LEN:
            state["status"] = AgentStatus.ERROR.value
            state["error_log"] = state.get("error_log", []) + [
                f"PreProcessNode S-2: input length {len(user_input)} exceeds {_MAX_INPUT_LEN} limit"
            ]
            return state
        if has_leaked_secret_or_internal_identifier(user_input):
            state["status"] = AgentStatus.ERROR.value
            state["error_log"] = state.get("error_log", []) + [
                "PreProcessNode S-2: credential/secret or internal-only identifier rejected"
            ]
        return state
