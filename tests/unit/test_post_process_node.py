# SVC-C2-101 — Unit Tests: PostProcessNode (PIRAssemble/OutputValidate S-3 + IncidentAudit S-4)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.post_process_node import PostProcessNode


def _state(**kw):
    base = {
        "correlation_id": "test-correlation", "session_id": "test-session",
        "trace_id": "test-trace", "node_history": [], "error_log": [],
    }
    base.update(kw)
    return base


_FULL_DRAFT = (
    "### Timeline\n- incident timeline here (ARCH-PAYGW-2026-03)\n\n"
    "### Root Cause (5-Why)\n- root cause detail\n\n"
    "### Contributing Factors\n- factor one\n\n"
    "### Corrective Actions\n- action one"
)


def _drafted_state():
    return _state(
        disposition="DRAFTED",
        kb_version_manifest=["Payment Gateway (2026-07-01)"],
        draft_pir=_FULL_DRAFT,
        retrieved_context=[
            {"citation": "ARCH-PAYGW-2026-03", "service": "Payment Gateway",
             "kb_date": "2026-07-01", "snippet": "..."},
        ],
    )


class TestPostProcessNodeReviewNoteAndAudit:
    def test_review_note_appended(self):
        r = PostProcessNode().execute(_drafted_state())
        assert r["status"] == AgentStatus.SUCCESS.value
        assert "draft" in r["validated_pir"].lower()
        assert "pending on-call engineer review" in r["validated_pir"].lower()

    def test_citation_count_computed(self):
        r = PostProcessNode().execute(_drafted_state())
        assert r["citation_count"] == 1

    def test_error_state_short_circuits(self):
        r = PostProcessNode().execute(_state(status=AgentStatus.ERROR.value))
        assert r == {}


class TestPostProcessNodeS3Grounding:
    def test_uncited_answer_blocked(self):
        node = PostProcessNode()
        result = {
            "validated_pir": (
                "### Timeline\n- t\n\n### Root Cause (5-Why)\n- r\n\n"
                "### Contributing Factors\n- f\n\n### Corrective Actions\n- a"
            ),
            "status": AgentStatus.SUCCESS.value,
        }
        raised = False
        try:
            node._extra_security_gate_output(result)
        except RuntimeError:
            raised = True
        assert raised, "S-3 ResponseValidate must block a draft with no architecture/incident citation"

    def test_missing_section_blocked(self):
        node = PostProcessNode()
        result = {
            "validated_pir": "### Timeline\n- t (ARCH-PAYGW-2026-03)\n\n### Root Cause (5-Why)\n- r",
            "status": AgentStatus.SUCCESS.value,
        }
        raised = False
        try:
            node._extra_security_gate_output(result)
        except RuntimeError:
            raised = True
        assert raised, "S-3 structural check must block a draft missing required sections"

    def test_cited_and_complete_answer_passes(self):
        node = PostProcessNode()
        result = {"validated_pir": _FULL_DRAFT, "status": AgentStatus.SUCCESS.value}
        node._extra_security_gate_output(result)  # must not raise

    def test_credential_pattern_blocked(self):
        node = PostProcessNode()
        result = {"validated_pir": "the password is hunter2 (ARCH-PAYGW-2026-03)",
                  "status": AgentStatus.SUCCESS.value}
        raised = False
        try:
            node._extra_security_gate_output(result)
        except RuntimeError:
            raised = True
        assert raised, "S-3 must block a credential pattern from reaching output"

    def test_overclaim_certainty_blocked(self):
        node = PostProcessNode()
        result = {"validated_pir": "This will never happen again (ARCH-PAYGW-2026-03).",
                  "status": AgentStatus.SUCCESS.value}
        raised = False
        try:
            node._extra_security_gate_output(result)
        except RuntimeError:
            raised = True
        assert raised, "S-3 must block unsupported prevention-guarantee phrasing"

    def test_bare_state_degenerate_call_does_not_raise(self):
        """Generic tests/proof_of_boundary/test_pb_invoke_order.py calls
        PostProcessNode() directly with a bare state (no upstream main output). The
        grounding + structural checks must NOT raise on this degenerate case."""
        node = PostProcessNode()
        result = node.execute(_state())
        node._extra_security_gate_output(result)  # must not raise


class TestPostProcessNodeTrust:
    def test_internal_trust_declared(self):
        assert PostProcessNode.required_trust_level == TrustLevel.INTERNAL
