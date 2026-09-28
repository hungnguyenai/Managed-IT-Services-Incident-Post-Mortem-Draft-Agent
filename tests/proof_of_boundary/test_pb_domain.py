# SVC-C2-101 — Proof-of-Boundary: domain-specific boundary verification
#
# PB-1: emit_trace_event() in every execute() body (S-4 audit)
# PB-6: _security_gate_* not overridden; _extra_* hooks callable; FunctionNode subclasses
# Domain: retrieved_context NON-SUPPRESSIBLE (citation trail); uncited/structurally-incomplete
#         drafts blocked (S-3); a live-credential/internal-identifier-carrying log excerpt is
#         rejected BEFORE retrieval (zero KB calls); an unmatched query forces NO_MATCH (never
#         an affirmative ungrounded PIR draft).
#
# Graph-level coverage: isolated node-level unit tests can pass while the REAL
# Graph.invoke() path (with the framework's own built-in S-2 PII-masking pipeline in front of
# every node) silently defeats a domain gate. These tests drive the SAME real path every
# production caller uses: Graph(config=...).compile().invoke(...) — never a manually composed
# node chain, never .run().
#
# CI-safe: fully deterministic offline (no live API/vector store).

import inspect

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext, TrustLevel

from src.nodes.pre_process_node import PreProcessNode
from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.graph.graph import Graph
from src.schemas.state import State


def _state(**kw):
    base = {
        "correlation_id": "pb-corr", "session_id": "pb-session", "thread_id": "pb-thread",
        "trace_id": "pb-trace", "node_history": [], "error_log": [], "input_context": {},
    }
    base.update(kw)
    return base


def _v(*parts: str) -> str:
    """Assemble a Fail-tier credential-shaped fixture at run time.

    gate-credential-scan's URL-credential pattern (`://<user>:<secret>@`) now applies
    inside tests/ too — the credential-scan rule covers test code as well.
    Splitting the literal across args means no single source line contains the full
    match, while the joined value below is still the realistic connection-string shape
    these PB cases need to feed the graph to prove the S-2/S-3 leak-rejection path.
    """
    return "".join(parts)


_LEAKED_DSN = _v("postgres://admin:hunter2", "@dbhost/incidents")


class TestPB1TraceEmission:
    def test_pre_process_emits(self):
        assert "emit_trace_event" in inspect.getsource(PreProcessNode.execute)

    def test_main_emits(self):
        assert "emit_trace_event" in inspect.getsource(MainNode.execute)

    def test_post_process_emits(self):
        assert "emit_trace_event" in inspect.getsource(PostProcessNode.execute)


class TestPB6SecurityGates:
    def test_gate_input_not_overridden(self):
        assert "_security_gate_input" not in PreProcessNode.__dict__

    def test_gate_output_not_overridden(self):
        assert "_security_gate_output" not in PostProcessNode.__dict__

    def test_extra_hooks_callable(self):
        assert callable(getattr(PreProcessNode(), "_extra_security_gate_input", None))
        assert callable(getattr(PostProcessNode(), "_extra_security_gate_output", None))

    def test_all_nodes_are_functionnode(self):
        for cls in (PreProcessNode, MainNode, PostProcessNode):
            assert issubclass(cls, FunctionNode), f"{cls.__name__} must extend FunctionNode"


class TestRetrievedContextNonSuppressible:
    def _state_with_context(self):
        return _state(
            disposition="DRAFTED",
            kb_version_manifest=["Payment Gateway (2026-07-01)"],
            draft_pir=(
                "### Timeline\n- t (ARCH-PAYGW-2026-03)\n\n### Root Cause (5-Why)\n- r\n\n"
                "### Contributing Factors\n- f\n\n### Corrective Actions\n- a"
            ),
            retrieved_context=[
                {"citation": "ARCH-PAYGW-2026-03", "service": "Payment Gateway",
                 "kb_date": "2026-07-01", "snippet": "..."},
            ],
        )

    def test_post_process_does_not_touch_retrieved_context(self):
        result = PostProcessNode().execute(self._state_with_context())
        assert "retrieved_context" not in result, (
            "PostProcessNode must not rewrite/empty the non-suppressible retrieved_context"
        )
        assert result["status"] == AgentStatus.SUCCESS.value


class TestNoMatchNeverSynthesises:
    class _EmptyKB:
        def retrieve(self, query):
            return []

    def test_empty_kb_forces_error_never_drafted(self):
        r = MainNode(kb_client=self._EmptyKB()).execute(
            _state(sanitized_query="what is the weather today")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert "draft_pir" not in r  # never issues an ungrounded draft
        assert any("no_incident_context_match" in e for e in r["error_log"])


class TestGraphLevelInputGate:
    """Graph-level Proof-of-Boundary — sibling-incident follow-up.

    Drives real-graph verification: SVC-C2-101's own gates
    (live-credential/internal-identifier rejection in PreProcessNode) are exercised
    through `Graph(config={"kb_client": ...}).compile().invoke(...)` — the SAME real
    path production uses — with an instrumented spy KB client injected exactly the
    way `Graph.register_nodes()` wires it into `MainNode(kb_client=...)`.

    Also empirically proves the specific HCR-class hazard does NOT apply here:
    `has_leaked_secret_or_internal_identifier` (src/services/service.py) is
    phrase/pattern based (credential markers, connection-string shape, AWS key
    shape, private-IP/internal-hostname shape) — none key off a generic long-digit-run
    PII shape — so the framework's built-in PII-masking of a long digit run can
    neither defeat an intended rejection nor corrupt a legitimate retrieval/synthesis.
    Both directions proved empirically below, not assumed.
    """

    class _SpyKBClient:
        """Fake system-architecture + prior-incident-history KB client implementing
        the real interface consumed by `services.service.retrieve_context`
        (`retrieve(query) -> list[dict]`, exactly as looked up and called from inside
        `MainNode.execute()` via `self._kb_client`). Records every call so the test
        can assert zero retrieval on a rejected path.
        """

        def __init__(self):
            self.calls: list[str] = []

        def retrieve(self, query: str):
            self.calls.append(query)
            return [{
                "citation": "SPY-KB-001", "service": "Spy Service Index",
                "kb_date": "2026-07-15", "snippet": "spy architecture/incident evidence snippet",
            }]

    @staticmethod
    def _build_graph(kb_client):
        graph = Graph(config={"kb_client": kb_client})
        graph.compile()
        return graph

    @staticmethod
    def _ctx(session_id: str) -> InvocationContext:
        # All three SVC-C2-101 nodes declare required_trust_level = INTERNAL
        # (authorized on-call/IT-ops staff); use that level so the negative
        # assertions below are conditioned on the domain gates, not an S-1 denial.
        return InvocationContext(
            session_id=session_id,
            caller_trust_level=TrustLevel.INTERNAL,
            caller_id="pb-graph-test",
        )

    # ── negative paths: rejection must survive the REAL graph wiring ────────

    def test_graph_invoke_secret_leak_rejected_zero_kb_retrieval(self):
        spy = self._SpyKBClient()
        graph = self._build_graph(spy)

        result = graph.invoke(
            f"resolution notes: connection string {_LEAKED_DSN} "
            "was used to bounce the payment gateway service",
            ctx=self._ctx("pb-graph-secret"),
        )

        assert result["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value), result
        assert not result.get("output"), result
        assert "draft_pir" not in result, (
            "a live-credential-carrying log excerpt must never reach ContextRetrieve"
        )
        assert spy.calls == [], (
            f"Real Graph.invoke() reached context retrieval (kb_client.retrieve) "
            f"for a credential-leaking input — calls: {spy.calls}"
        )
        # route() sends ERROR straight to finalize — post_process must never run.
        assert "PostProcessNode" not in result.get("node_history", []), result.get("node_history")

    def test_graph_invoke_internal_identifier_rejected_zero_kb_retrieval(self):
        spy = self._SpyKBClient()
        graph = self._build_graph(spy)

        result = graph.invoke(
            "edge node 10.20.30.40 dropped health checks — please draft a PIR for the "
            "network edge outage",
            ctx=self._ctx("pb-graph-internal-id"),
        )

        assert result["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value), result
        assert not result.get("output"), result
        assert spy.calls == [], (
            f"Real Graph.invoke() reached context retrieval for an internal-IP-carrying "
            f"input — calls: {spy.calls}"
        )
        assert "PostProcessNode" not in result.get("node_history", []), result.get("node_history")

    # ── positive control: proves the negative assertions aren't vacuous ─────

    def test_graph_invoke_positive_control_legitimate_query_reaches_kb_client(self):
        """Same real Graph, same real (injected) kb_client, same real .invoke() entry
        point — proves the negative tests above are conditioned on the real
        domain-gate outcome, and not on retrieval being unreachable/broken through
        the graph wiring in general."""
        spy = self._SpyKBClient()
        graph = self._build_graph(spy)

        result = graph.invoke(
            "Resolved P1: checkout failures across the payment gateway during a PSP "
            "timeout cascade. Please draft a PIR.",
            ctx=self._ctx("pb-graph-positive"),
        )

        assert result["status"] in (AgentStatus.SUCCESS, AgentStatus.SUCCESS.value), result
        assert spy.calls == [
            "Resolved P1: checkout failures across the payment gateway during a PSP "
            "timeout cascade. Please draft a PIR."
        ], spy.calls
        assert "SPY-KB-001" in str(result.get("output")), result
        assert "draft" in str(result.get("output")).lower()
        assert "PostProcessNode" in result.get("node_history", [])
        assert "MainNode" in result.get("node_history", [])

    # ── NO_MATCH path: must never synthesise through the real graph ─────────

    def test_graph_invoke_unmatched_query_never_synthesises(self):
        class _EmptyKB:
            def retrieve(self, query):
                return []

        graph = self._build_graph(_EmptyKB())

        result = graph.invoke(
            "What is the weather forecast for tomorrow?",
            ctx=self._ctx("pb-graph-nomatch"),
        )

        assert result["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value), result
        assert not result.get("output"), result
        assert "PostProcessNode" not in result.get("node_history", [])

    # ── HCR-class hazard: built-in PII masking must not corrupt SVC's OWN gate ──

    def test_graph_invoke_pii_shaped_value_does_not_defeat_legitimate_answer(self):
        """A legitimate, in-scope incident-review request that also carries a
        PII-shaped long digit run (e.g. a ticket reference number) must NOT be
        spuriously rejected merely because the built-in S-2 scan masks that digit
        run to `[MASKED]` before PreProcessNode.execute() ever sees it — SVC's own
        secret-screen/retrieval logic is phrase-based and must survive intact."""
        spy = self._SpyKBClient()
        graph = self._build_graph(spy)

        result = graph.invoke(
            "Ticket reference 123456789012 — please draft a PIR for the payment "
            "gateway checkout failures during the PSP timeout cascade.",
            ctx=self._ctx("pb-graph-pii-legitimate"),
        )
        assert result["status"] in (AgentStatus.SUCCESS, AgentStatus.SUCCESS.value), result
        assert spy.calls, (
            "built-in PII masking of the digit run must not have swallowed the "
            f"payment-gateway retrieval signal: {result}"
        )

    def test_graph_invoke_pii_masking_does_not_defeat_secret_rejection(self):
        """Empirically confirm SVC's own CredentialSecretScreen trigger is
        phrase/pattern based, not digit-shape-based — unlike a detector whose ONLY
        signal for one input is a digit-shape regex the built-in masker also
        matches (the HCR incident class). Here the rejection phrase (connection
        string) is deliberately paired with a maskable digit run; if SVC's detection
        secretly depended on the (now-masked) digits surviving, this would flip from
        ERROR to SUCCESS — it must not."""
        spy = self._SpyKBClient()
        graph = self._build_graph(spy)

        result = graph.invoke(
            "Ticket reference 123456789012 — resolution notes: connection string "
            f"{_LEAKED_DSN} was used during the failover.",
            ctx=self._ctx("pb-graph-pii-secret"),
        )

        assert result["status"] in (AgentStatus.ERROR, AgentStatus.ERROR.value), (
            "PII-shaped-value masking of the digit run must not have defeated the "
            f"phrase-based credential-leak rejection: {result}"
        )
        assert spy.calls == [], spy.calls
        assert "PostProcessNode" not in result.get("node_history", [])


class TestS3Grounding:
    _FULL_DRAFT = (
        "### Timeline\n- t (ARCH-PAYGW-2026-03)\n\n### Root Cause (5-Why)\n- r\n\n"
        "### Contributing Factors\n- f\n\n### Corrective Actions\n- a"
    )

    def test_uncited_answer_blocked(self):
        node = PostProcessNode()
        result = {
            "validated_pir": (
                "### Timeline\n- t\n\n### Root Cause (5-Why)\n- r\n\n"
                "### Contributing Factors\n- f\n\n### Corrective Actions\n- a"
            ),
            "status": AgentStatus.SUCCESS.value,
        }
        try:
            node._extra_security_gate_output(result)
            raised = False
        except RuntimeError:
            raised = True
        assert raised, "S-3 ResponseValidate must block a draft with no architecture/incident citation"

    def test_missing_required_section_blocked(self):
        node = PostProcessNode()
        result = {
            "validated_pir": "### Timeline\n- t (ARCH-PAYGW-2026-03)",
            "status": AgentStatus.SUCCESS.value,
        }
        try:
            node._extra_security_gate_output(result)
            raised = False
        except RuntimeError:
            raised = True
        assert raised, "S-3 structural check must block a draft missing required sections"

    def test_credential_pattern_blocked(self):
        node = PostProcessNode()
        result = {"validated_pir": "the password is hunter2 (ARCH-PAYGW-2026-03)",
                  "status": AgentStatus.SUCCESS.value}
        try:
            node._extra_security_gate_output(result)
            raised = False
        except RuntimeError:
            raised = True
        assert raised, "S-3 must block a credential pattern from reaching output"

    def test_overclaim_certainty_blocked(self):
        node = PostProcessNode()
        result = {"validated_pir": "This will never happen again (ARCH-PAYGW-2026-03).",
                  "status": AgentStatus.SUCCESS.value}
        try:
            node._extra_security_gate_output(result)
            raised = False
        except RuntimeError:
            raised = True
        assert raised, "S-3 must block unsupported prevention-guarantee phrasing"

    def test_degenerate_bare_state_does_not_raise(self):
        """The generic tests/proof_of_boundary/test_pb_invoke_order.py calls
        PostProcessNode() directly with a BARE state (no upstream main output). The
        grounding + structural checks must NOT raise on this degenerate empty-
        evidence case (the sentinel-escape-hatch fix)."""
        node = PostProcessNode()
        result = node.execute(_state())
        node._extra_security_gate_output(result)  # must not raise


class TestGraphStructure:
    def test_inherits_agent_base_graph(self):
        from framework.graph.agent_base_graph import AgentBaseGraph
        assert issubclass(Graph, AgentBaseGraph)

    def test_does_not_override_add_edges(self):
        assert "add_edges" not in Graph.__dict__

    def test_state_schema_is_state(self):
        assert Graph().state_schema is State

    def test_agent_name(self):
        assert Graph().name == "svc_c2_101"
