# SVC-C2-101 — Unit Tests: MainNode (ContextRetrieve + RootCauseReconstruct)

import inspect

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.main_node import MainNode


def _state(**kw):
    base = {
        "correlation_id": "test-correlation", "session_id": "test-session",
        "trace_id": "test-trace", "node_history": [], "error_log": [],
    }
    base.update(kw)
    return base


class TestMainNodeRetrievalAndReconstruction:
    def test_paygw_query_retrieves_and_drafts(self):
        r = MainNode().execute(
            _state(sanitized_query="checkout failures across the payment gateway PSP timeout")
        )
        assert r["status"] == AgentStatus.SUCCESS.value
        assert r["disposition"] == "DRAFTED"
        assert r["retrieved_context"]
        assert any(p["citation"] == "ARCH-PAYGW-2026-03" for p in r["retrieved_context"])
        assert "ARCH-PAYGW-2026-03" in r["draft_pir"]

    def test_cross_service_query_matches_multiple_services(self):
        r = MainNode().execute(
            _state(sanitized_query="payment gateway checkout failures during a database cluster failover storm")
        )
        assert r["status"] == AgentStatus.SUCCESS.value
        citations = {p["citation"] for p in r["retrieved_context"]}
        assert "ARCH-PAYGW-2026-03" in citations
        assert "ARCH-DBCLUSTER-2026-04" in citations
        assert len(r["kb_version_manifest"]) == 2

    def test_unmatched_query_forces_no_match(self):
        r = MainNode().execute(_state(sanitized_query="what is the weather today?"))
        assert r["status"] == AgentStatus.ERROR.value
        assert r["disposition"] == "NO_MATCH"
        assert r["retrieved_context"] == []
        assert any("no_incident_context_match" in e for e in r["error_log"])

    def test_error_state_short_circuits(self):
        r = MainNode().execute(_state(status=AgentStatus.ERROR.value))
        assert r == {}


class TestMainNodeKBClientInjection:
    class _EmptyKB:
        def retrieve(self, query):
            return []

    def test_empty_injected_kb_forces_no_match_never_drafts(self):
        r = MainNode(kb_client=self._EmptyKB()).execute(
            _state(sanitized_query="auth service login failure")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["disposition"] == "NO_MATCH"
        assert "draft_pir" not in r  # never issues an ungrounded draft


class TestMainNodeContract:
    def test_execute_method_signature(self):
        assert hasattr(MainNode, "execute"), "MainNode must implement execute()"
        sig = inspect.signature(MainNode.execute)
        params = list(sig.parameters.keys())
        assert len(params) >= 2
        assert params[1] == "state"
        assert "_invoke_impl" not in MainNode.__dict__

    def test_internal_trust_declared(self):
        assert MainNode.required_trust_level == TrustLevel.INTERNAL
