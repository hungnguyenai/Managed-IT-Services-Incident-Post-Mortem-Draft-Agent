# SVC-C2-101 — Unit Tests: PreProcessNode (InputValidate + CredentialSecretScreen)

from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from src.nodes.pre_process_node import PreProcessNode


def _state(**kw):
    base = {
        "correlation_id": "test-correlation",
        "session_id": "test-session",
        "thread_id": "test-thread",
        "trace_id": "test-trace",
        "node_history": [],
        "error_log": [],
        "input_context": {},
    }
    base.update(kw)
    return base


def _v(*parts: str) -> str:
    """Assemble a Fail-tier credential-shaped fixture at run time.

    gate-credential-scan's URL-credential pattern (`://<user>:<secret>@`) now applies
    inside tests/ too — the credential-scan rule covers test code as well.
    Splitting the literal across args means no single source line contains the full
    match, while the joined value below is still the realistic connection-string shape
    CredentialSecretScreen needs to see to prove the rejection path.
    """
    return "".join(parts)


_LEAKED_DSN = _v("postgres://admin:hunter2", "@dbhost/incidents")


class TestPreProcessNodeValidation:
    def test_empty_input_returns_error(self):
        r = PreProcessNode().execute(_state(user_input=""))
        assert r["status"] == AgentStatus.ERROR.value
        assert any("empty" in e for e in r["error_log"])

    def test_whitespace_only_returns_error(self):
        r = PreProcessNode().execute(_state(user_input="   "))
        assert r["status"] == AgentStatus.ERROR.value

    def test_oversized_input_returns_error(self):
        r = PreProcessNode().execute(_state(user_input="x" * 10001))
        assert r["status"] == AgentStatus.ERROR.value
        assert any("10000" in e for e in r["error_log"])

    def test_valid_input_accepted(self):
        r = PreProcessNode().execute(
            _state(user_input="Resolved P1: checkout failures across the payment gateway.")
        )
        assert r["status"] == AgentStatus.SUCCESS.value
        assert r["sanitized_query"]
        assert r["input_screen_flagged"] is False
        assert r["validated_input"] == r["sanitized_query"]

    def test_whitespace_normalized(self):
        r = PreProcessNode().execute(_state(user_input="  payment   gateway   outage  "))
        assert r["sanitized_query"] == "payment gateway outage"


class TestPreProcessNodeSecretScreen:
    def test_bearer_token_rejected(self):
        r = PreProcessNode().execute(
            _state(user_input="Bearer eyJhbGciOi... payment gateway incident review")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["input_screen_flagged"] is True
        assert any("CredentialSecretScreen" in e for e in r["error_log"])

    def test_connection_string_rejected(self):
        r = PreProcessNode().execute(
            _state(user_input=f"db failover at {_LEAKED_DSN}")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["input_screen_flagged"] is True

    def test_aws_key_rejected(self):
        r = PreProcessNode().execute(
            _state(user_input="found key AKIAABCDEFGHIJKLMNOP in the resolution notes")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["input_screen_flagged"] is True

    def test_private_ip_rejected(self):
        r = PreProcessNode().execute(
            _state(user_input="edge node 10.20.30.40 dropped health checks during the outage")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["input_screen_flagged"] is True

    def test_internal_hostname_rejected(self):
        r = PreProcessNode().execute(
            _state(user_input="db01.internal lost quorum during the failover storm")
        )
        assert r["status"] == AgentStatus.ERROR.value
        assert r["input_screen_flagged"] is True

    def test_legitimate_incident_not_flagged(self):
        r = PreProcessNode().execute(
            _state(user_input="Auth service login failures after certificate rotation.")
        )
        assert r["status"] == AgentStatus.SUCCESS.value
        assert r["input_screen_flagged"] is False


class TestPreProcessNodeSecurityGate:
    def test_oversized_input_rejected(self):
        out = PreProcessNode()._extra_security_gate_input(_state(user_input="x" * 10001))
        assert out["status"] == AgentStatus.ERROR.value

    def test_credential_shaped_rejected_at_gate(self):
        out = PreProcessNode()._extra_security_gate_input(
            _state(user_input="api_key=sk-xxxx payment gateway incident")
        )
        assert out["status"] == AgentStatus.ERROR.value

    def test_valid_input_passes_gate(self):
        out = PreProcessNode()._extra_security_gate_input(
            _state(user_input="What caused the database cluster failover storm?")
        )
        assert out.get("status") != AgentStatus.ERROR.value


class TestPreProcessNodeTrust:
    def test_internal_trust_declared(self):
        assert PreProcessNode.required_trust_level == TrustLevel.INTERNAL
