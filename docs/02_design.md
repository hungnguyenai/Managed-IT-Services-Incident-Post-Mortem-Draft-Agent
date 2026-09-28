# docs/02_design.md — SVC-C2-101 Design Specification

**Template ID**: SVC-C2-101
**Name**: Managed IT Services Incident Post-Mortem Draft Agent
**Category**: Cat 2 | **Industry**: SVC | **Pattern**: VectorRAG
**L1 Base:** AgentBaseGraph (L1 direct)
**Status**: Design — new-gen scaffold

---

## 1. Overview

After a P1/P2 incident resolves, the on-call engineer triggers this agent with the incident ticket
data, alert-log summary, and resolution notes. It retrieves relevant system-architecture context and
prior-incident history from a KB and produces a structured Post-Incident Review (PIR) draft — timeline
reconstruction, root cause with 5-Why, contributing factors, customer-impact assessment, and corrective
actions with ownership suggestions. It replaces a 2-4h manual PIR by a fatigued engineer and helps meet
48-72h SLA reporting deadlines. The beneficiary is the MSP / internal IT-ops function.

Example: *"Resolved P1: checkout failures across the payment gateway during a PSP timeout cascade.
Please draft a PIR — timeline, root cause, contributing factors, and corrective actions,
cross-referencing prior payment gateway circuit-breaker incidents."* → a cited PIR draft reconciling
the Payment Gateway architecture context (`ARCH-PAYGW-2026-03`, KB version 2026-07-01) with the prior
PSP-timeout-cascade incident precedent, plus corrective-action ownership suggestions.

---

## 2. Architecture — L1 Base

**L1 Base:** `AgentBaseGraph` (`framework/graph/agent_base_graph.py`), inherited directly.

Per the 2026-05-18 architecture change, templates inherit directly from L1; the retired base-agent
layer is no longer an inheritance path. `VectorRAGAgent` survives only as the **node-backbone pattern**
label (`config/agent.yaml` `base_type`). The outer graph `Graph(AgentBaseGraph)` registers three domain
nodes into the fixed framework backbone; `InitializeNode`/`FinalizeNode` are injected by
`super().register_nodes()`. `add_edges()` is NOT overridden.

The canonical incident-review flow (InputValidate → CredentialSecretScreen → ContextRetrieve →
RootCauseReconstruct → OutputValidate(S-3) → IncidentAudit(S-4)) is consolidated onto the fixed 3
domain slots: InputValidate+CredentialSecretScreen fold into `pre_process`; ContextRetrieve+
RootCauseReconstruct fold into `main`; OutputValidate+IncidentAudit fold into `post_process`. All 6
canonical steps are preserved across the 3 nodes — no step is dropped.

---

## 3. Node Flow (5-node backbone)

```
START → initialize → pre_process → main → post_process → finalize → END
```

| Slot | Node | Canonical step(s) | Responsibility |
|------|------|-------------------|-----------------|
| `initialize`   | InitializeNode (framework) | — | Seed IDs / context |
| `pre_process`  | PreProcessNode (FunctionNode) | InputValidate + CredentialSecretScreen | Validate + sanitise + S-2 deterministic live-credential/internal-identifier reject |
| `main`         | MainNode (FunctionNode) | ContextRetrieve + RootCauseReconstruct | Retrieve system-architecture + prior-incident-history passages (VectorRAG); reconstruct timeline + 5-Why root cause + contributing factors + corrective actions; `NO_MATCH` if nothing matched |
| `post_process` | PostProcessNode (FunctionNode) | OutputValidate + S-3 + IncidentAudit + S-4 | Append non-suppressible draft-review note; block uncited/credential/overclaim output; structural completeness check; emit audit record |
| `finalize`     | FinalizeNode (framework) | — | Finalize status |

`main` is a `FunctionNode` (no inner graph). The system-architecture + prior-incident-history KB client
is injected via graph config; absent → deterministic fallback corpus. Any node returning
`AgentStatus.ERROR` short-circuits the remaining domain nodes (a `CredentialSecretScreen` reject or a
`NO_MATCH` never reaches `post_process`).

---

## 4. State Schema

`src/schemas/state.py` — `class State(AgentState)`. The incident ticket data + alert-log summary +
resolution notes arrive as inherited `user_input`.

| Field (agent-specific) | Type | Set by | Description |
|-------------------------|------|--------|-------------|
| `sanitized_query` | `Optional[str]` | pre_process | Whitespace-normalised, screened request |
| `input_screen_flagged` | `Optional[bool]` | pre_process | True when CredentialSecretScreen rejected the query |
| `retrieved_context` | `Optional[list[dict]]` | main | `{citation, service, kb_date, snippet}` — **non-suppressible citation trail** |
| `kb_version_manifest` | `Optional[list[str]]` | main | One entry per service/component cited (S-4 audit + data-currency) |
| `disposition` | `Optional[str]` | main | `DRAFTED` \| `NO_MATCH` |
| `draft_pir` | `Optional[str]` | main | Draft PIR (pre-S-3) — timeline + 5-Why + contributing factors + corrective actions |
| `validated_pir` | `Optional[str]` | post_process | Final PIR draft incl. non-suppressible review note |
| `citation_count` | `Optional[int]` | post_process | Number of distinct architecture/incident citations in the draft |

All fields flat, msgpack-safe primitives (ADR-005) — no non-flat objects, no datetime/bytes, no
credentials or connection strings. Live secrets and internal-only host/IP identifiers are screened out
at `pre_process` before they ever enter state.

---

## 5. Domain Logic — Screening, Retrieval & Reconstruction

`src/services/service.py` — deterministic offline corpus (`INCIDENT_KB`) spanning Payment Gateway /
Auth-IAM Service / Database Cluster / Network Edge-CDN, each passage carrying `citation`/`service`/
`kb_date`/`snippet` (architecture context + prior-incident precedent).

- **CredentialSecretScreen** (`has_leaked_secret_or_internal_identifier`): deterministic regex/keyword
  ruleset (rule/keyword, not LLM) for live credentials (Bearer token, connection string, API key,
  private key) and internal-only host/IP identifiers (RFC1918 IP, `.internal`/`.corp` hostnames). Runs
  in `pre_process`, BEFORE retrieval — a query flagged here never reaches `ContextRetrieve`.
- **ContextRetrieve** (`retrieve_context`): keyword-matched retrieval across all four service lexicons
  at once — a query may legitimately match multiple services (the cross-service incident case, e.g. a
  payment-gateway failure triggered by a database failover storm). No match across any service →
  `NO_MATCH`.
- **RootCauseReconstruct** (`reconstruct_pir`): deterministic grounded synthesis, NOT a pure
  single-passage lookup — reconstructs a timeline, 5-Why root cause (grounded in the retrieved
  architecture + prior-incident snippets), contributing factors, customer-impact placeholder, and
  corrective actions with ownership suggestions. This deterministic synthesiser is the offline/CI
  fallback for an injected LLM reasoner (deferred — §11); the section/citation contract stays stable
  either way.

In production the injected `kb_client` replaces the corpus (same `retrieve(query) -> list[dict]`
interface). Only architecture/incident-history citations + snippets are ever surfaced — never
source-system credentials or internal infra identifiers.

---

## 6. Security Model (5-layer)

| Layer | Where | Design |
|-------|-------|--------|
| S-1 Trust | every node | `required_trust_level = INTERNAL` (authorized on-call/IT-ops staff) — declared on all three FunctionNode subclasses + `config/agent.yaml` |
| S-2 Input | `PreProcessNode._extra_security_gate_input` + `execute()` | Length-cap + live-credential/internal-identifier guard (returns state; never raises); execute() also runs the deterministic CredentialSecretScreen |
| S-3 Output | `PostProcessNode._extra_security_gate_output` | Block credential patterns leaking from logs; block unsupported prevention-guarantee phrasing; structural completeness check (Timeline + 5-Why + Contributing Factors + Corrective Actions); **ResponseValidate** rejects a draft with no architecture/incident-history citation (grounding); the non-suppressible review note is appended in `execute()` |
| S-4 Audit | every `execute()` | `emit_trace_event()` domain events (input_validated, secret_or_internal_rejected, context_retrieved, no_incident_context_match, root_cause_reconstruct_complete, incident_audit …) — no PII, no credentials, no internal identifiers |
| S-5 Credential | CI `gate-credential-scan` + deps | No hardcoded secrets; deps `==`-pinned; no secrets/connection strings in State or corpus |

`retrieved_context` is written once by `main` and never filtered downstream (citation-trail integrity —
a PIR draft must stay grounded in the architecture/incident-history basis it cites).

---

## 7. KB Dependency (versioned offline snapshot)

Data dependency on the versioned system-architecture + prior-incident-history corpus — a template-owned
index. **No cross-template code import**; the indexer is not called at runtime. Readiness gate: corpus
must be current before deploy. Fallback: `NO_MATCH` disposition when the injected client (or the
deterministic corpus) yields nothing — the agent never drafts a PIR without current architecture/
incident-history grounding. The KB version manifest is recorded in state + audit.

---

## 8. Interfaces

**Input** (`user_input`): incident ticket data + alert-log summary + resolution notes (free text).
**Output** (`result.output` / `formatted_output`): a draft PIR — timeline + 5-Why root cause +
contributing factors + customer impact + corrective actions + non-suppressible "draft, pending review"
note.
Entry points: `src/api/server.py` (`POST /invoke`, `GET /health`) and direct `agent.invoke()`.

---

## 9. Failure / Error Routing

| Condition | Node | Behaviour |
|-----------|------|-----------|
| Empty / whitespace input | pre_process | `status=ERROR`, error_log entry; downstream nodes short-circuit |
| Oversized input (> 10,000 chars) | pre_process (execute + S-2 gate) | `status=ERROR` |
| Live credential/secret or internal-only identifier in logs | pre_process (CredentialSecretScreen) | `status=ERROR`, `input_screen_flagged=True`; retrieval never runs |
| Below-trust caller (< INTERNAL) | S-1 gate (framework) | refused before domain execute |
| No architecture/incident-history passage matched | main | `NO_MATCH` `status=ERROR` — never draft without grounding |
| Uncited / credential / overclaim / structurally-incomplete output | post_process S-3 | `RuntimeError` raised, output blocked |

---

## 10. Acceptance Criteria

- Backbone runs `initialize → pre_process → main → post_process → finalize` in fixed order.
- Valid INTERNAL invocation for an in-scope, retrievable incident returns a cited PIR draft
  (`validated_pir` carries an `ARCH-PAYGW-`/`ARCH-AUTHIAM-`/`ARCH-DBCLUSTER-`/`ARCH-NETEDGE-`/`KB
  version` citation marker + all 4 required sections + the non-suppressible review note) with
  `status=SUCCESS`.
- A live-credential/internal-identifier-carrying log excerpt is rejected before retrieval — zero KB
  calls, `post_process` never runs.
- No PIR draft passes S-3 without at least one architecture/incident-history citation, and without all
  4 required sections present.
- An unmatched query forces `NO_MATCH` — never an affirmative draft without grounding.
- Root-cause reconstruction is grounded in the retrieved passages (no fabricated service/incident not
  present in `retrieved_context`).
- All CI gates green: scaffold-integrity, design, import-isolation, composition, invoke-chain,
  credential-scan, trust-level, cat-consistency, stub-check, dep-pinning, run-tests.

---

## 11. Deferred to later implementation issues

The day-0 implementation is CI-safe and deterministic offline. The following land via their own issues:

- **Versioned vector-KB retrieval** — replace the deterministic corpus with an injected versioned
  client over the real self-hosted system-architecture + prior-incident-history knowledge graph (with
  snapshot-freshness checks).
- **LLM root-cause reasoner** — richer 5-Why reasoning / rationale via an injected `BaseLLM`
  (`ctx.secrets.require(...)`); the deterministic synthesiser is retained as offline/CI fallback.
- **Scope boundary** — this agent is PIR-drafting only. Pre-breach SLA-risk
  alerting and SLA-breach penalty reporting are explicitly out of scope.

---

## Supported entry point — HTTP/gateway only (Marketplace out of scope)

Every node in this template declares `required_trust_level = INTERNAL`, which is the design
decision recorded for this agent: the data it reads is not material an arbitrary authenticated
caller should be able to query.

The one-shot Marketplace runner stamps the caller at `VERIFIED_EXTERNAL` and exposes no
configuration surface or elevation path to `INTERNAL`, so the S-1 gate refuses every Marketplace
invocation **before** `execute()` runs. Two consequences are worth stating, because both read as
a broken image: the Pod still reports success and the audit counters do not move, and the terminal
failure carries no reason, so the chat surface shows an opaque error.

Nesting does not change this. A subgraph is invoked with the caller's own context
(`subgraph.invoke(..., ctx=ctx)`), so the trust level propagates unchanged and an inner node
cannot be reached at a higher level than the outer call arrived with.

### The HTTP path is also closed, deliberately

The standalone adapter used to promote an anonymous caller straight to `INTERNAL` once it
presented the shared `INVOKE_AUTH_TOKEN`. That token authenticates a *deployment*, not a person,
so granting `INTERNAL` on it placed a back door behind the very gate this design depends on. The
adapter now grants `VERIFIED_EXTERNAL`, which is what its own documentation always described.
**The gate is unchanged** — every node still requires `INTERNAL`.

The consequence is stated rather than hidden: since the nodes require `INTERNAL` and nothing in
either entry point can now supply it, **this template currently has no reachable entry point at
all**. That is fail-closed and intended.

One legitimate route remains open: trust established by upstream middleware is passed through
unchanged, so a gateway that has verified the caller's identity can still reach these nodes.

### What is NOT being done

- The nodes' `required_trust_level` is **not** lowered. Doing so would widen who may query this
  data, which is a product decision and not an engineering one.
- No Marketplace image is published and the template is not registered as a Marketplace agent.
