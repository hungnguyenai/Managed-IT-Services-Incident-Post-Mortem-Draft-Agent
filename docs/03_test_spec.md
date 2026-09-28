# docs/03_test_spec.md — SVC-C2-101 Test Specification

Traceability: docs/02_design.md

---

## 1. Functional Coverage

| # | Scenario | Test | Expected |
|---|----------|------|----------|
| F1 | Single-service incident (Payment Gateway) | `test_main_node.py::test_paygw_query_retrieves_and_drafts` | `DRAFTED`, cites `ARCH-PAYGW-2026-03` |
| F2 | Cross-service incident (Payment Gateway + Database Cluster) | `test_main_node.py::test_cross_service_query_matches_multiple_services` | Both citations present, 2-entry KB manifest |
| F3 | Full backbone happy path | `test_invoke.py::test_invoke_happy_path_succeeds_with_internal_trust` | `SUCCESS`, all 5 nodes in `node_history`, cited PIR draft |
| F4 | Whitespace normalisation | `test_pre_process_node.py::test_whitespace_normalized` | Collapsed to single spaces |

## 2. Negative / Error-Path Coverage

| # | Scenario | Test | Expected |
|---|----------|------|----------|
| N1 | Empty / whitespace-only input | `test_pre_process_node.py::TestPreProcessNodeValidation` | `ERROR`, error_log entry |
| N2 | Oversized input (>10,000 chars) | `test_pre_process_node.py::test_oversized_input_returns_error` | `ERROR` |
| N3 | Live credential/secret or internal-only identifier in logs | `test_pre_process_node.py::TestPreProcessNodeSecretScreen` | `ERROR` |
| N4 | Unmatched query (no service hit) | `test_main_node.py::test_unmatched_query_forces_no_match` | `disposition=NO_MATCH`, `ERROR`, no `draft_pir` |
| N5 | Empty injected kb_client | `test_main_node.py::TestMainNodeKBClientInjection` | `NO_MATCH`, never drafts |

## 3. Security Coverage

| # | Layer | Test | Expected |
|---|-------|------|----------|
| S1 | S-1 trust gate | `test_pre_process_node.py::test_internal_trust_declared` + siblings | `required_trust_level == INTERNAL` on all 3 nodes |
| S2 | S-2 input scan | `test_pre_process_node.py::TestPreProcessNodeSecurityGate` | Oversized / credential-shaped input rejected at `_extra_security_gate_input` |
| S2b | CredentialSecretScreen (domain S-2) | `test_pre_process_node.py::TestPreProcessNodeSecretScreen` | Live credential/connection-string/internal-IP/hostname phrasing rejected before retrieval |
| S3 | S-3 grounding + structural | `test_post_process_node.py::TestPostProcessNodeS3Grounding` | Uncited draft, credential pattern, overclaim phrasing, and missing-section draft all raise |
| S3b | Non-suppressible review note | `test_post_process_node.py::test_review_note_appended` | Every `DRAFTED` response carries the non-suppressible review note |
| S4 | S-4 audit | `test_pb_domain.py::TestPB1TraceEmission` | `emit_trace_event` present in every node's `execute()` |
| S5 | Credential scan | CI `gate-credential-scan` | No hardcoded secrets in source |

## 4. Proof-of-Boundary Coverage (graph-level, real `Graph.invoke()`)

Node-level tests alone are
insufficient; these drive the real production entry point with the framework's built-in S-2
PII-masking pipeline in front of every node.

| # | Test (`tests/proof_of_boundary/test_pb_domain.py::TestGraphLevelInputGate`) | Proves |
|---|------------------------------------------------------------------------------|--------|
| PB-D1 | `test_graph_invoke_secret_leak_rejected_zero_kb_retrieval` | A live-credential-carrying log excerpt never reaches `ContextRetrieve` — zero `kb_client.retrieve` calls, `PostProcessNode` never runs |
| PB-D2 | `test_graph_invoke_internal_identifier_rejected_zero_kb_retrieval` | An internal-only IP/hostname-carrying log excerpt is rejected before retrieval |
| PB-D3 | `test_graph_invoke_positive_control_legitimate_query_reaches_kb_client` | The negative assertions above are conditioned on the real gate outcome, not on retrieval being unreachable in general |
| PB-D4 | `test_graph_invoke_unmatched_query_never_synthesises` | A query matching no service forces `NO_MATCH` through the real graph — never a fabricated PIR |
| PB-D5 | `test_graph_invoke_pii_shaped_value_does_not_defeat_legitimate_answer` | Built-in digit-run PII masking does not swallow a legitimate retrieval signal |
| PB-D6 | `test_graph_invoke_pii_masking_does_not_defeat_secret_rejection` | Built-in digit-run PII masking does not defeat the phrase-based credential-leak rejection (the HCR-class hazard, proved absent here) |

Also standard scaffold PB suites (generic, unmodified): `test_import_isolation.py` (L1-direct, no
Level-0/Level-2 imports), `test_state_safety.py` (no credentials/Pydantic/dataclass in State),
`test_pb_invoke_order.py` (S-1 → node_start → S-2 → execute → S-3 → node_complete order for every
node), `test_pb7_hitl_interrupt_propagation.py` (skip-guarded — `hitl.enabled` is `false` for this
template).

## 5. Acceptance Criteria for CI / STG

- All 12 CI gates green: scaffold-integrity, ci-stubs-deprecation, import-isolation, composition,
  invoke-chain, credential-scan, trust-level, cat-consistency, run-tests, test, stub-check,
  dep-pinning.
- `pytest tests/` and `pytest tests/proof_of_boundary/` both fully green, no skips other than the
  HITL PB-7 placeholder (this template has `hitl.enabled: false`).
- STG first-invoke: a legitimate incident-review query returns `status=SUCCESS`
  with a cited, review-note-carrying PIR draft.
