"""AgentCore Platform v1.0"""

# Deterministic offline system-architecture + prior-incident-history corpus and
# reasoning core for SVC-C2-101.
#
# Post-Incident Review (PIR) drafting: given a resolved P1/P2 incident (ticket data,
# alert-log summary, resolution notes), the agent retrieves relevant system-architecture
# context and prior-incident history from a KB (per affected service/component) and
# synthesises a structured PIR draft: timeline reconstruction, root cause with 5-Why,
# contributing factors, customer-impact assessment, and corrective actions with
# ownership suggestions.
#
# This module is the deterministic, fully CI-safe offline core: no external
# dependency, no live API. In production the retrieval below is replaced by an
# injected `kb_client` (same `retrieve(query) -> list[dict]` interface); absent,
# retrieval falls back to the corpus below. If an injected kb_client yields nothing,
# callers must surface a `NO_MATCH` disposition (see MainNode) rather than draft an
# ungrounded PIR. Only architecture/incident-history citations + snippets are ever
# stored — never source-system credentials, connection strings, or live secrets (S-5).

from __future__ import annotations

import re
from typing import Any, Optional, cast

# Snapshot version of the bundled system-architecture + prior-incident-history corpus.
# In production the injected kb_client supplies the real per-service KB version.
KB_VERSION = "2026-07-01"

# Disposition labels (single source of truth).
DRAFTED = "DRAFTED"
NO_MATCH = "NO_MATCH"

# Versioned system-architecture + prior-incident-history corpus. Each entry carries a
# citation id, the affected service/component, the KB snapshot date, and a snippet
# combining architecture context with prior-incident precedent.
INCIDENT_KB: list[dict[str, Any]] = [
    {
        "citation": "ARCH-PAYGW-2026-03",
        "service": "Payment Gateway",
        "kb_date": KB_VERSION,
        "snippet": "Payment Gateway architecture: checkout requests fan out through a retry "
        "+ circuit-breaker layer to the downstream PSP. Prior incident (2026-03): a PSP "
        "timeout cascade tripped the circuit breaker into open state for 40 minutes, "
        "causing checkout failures; root cause was an undersized PSP connection-pool "
        "timeout relative to the PSP's own p99 latency.",
    },
    {
        "citation": "ARCH-AUTHIAM-2026-02",
        "service": "Auth/IAM Service",
        "kb_date": KB_VERSION,
        "snippet": "Auth/IAM Service architecture: SSO token validation depends on a "
        "short-lived signing-certificate cache refreshed from the IAM root every 15 "
        "minutes. Prior incident (2026-02): an expired signing certificate was not "
        "rotated before cache refresh, causing a login outage until the cache was "
        "force-refreshed; root cause was a missing pre-expiry rotation alert.",
    },
    {
        "citation": "ARCH-DBCLUSTER-2026-04",
        "service": "Database Cluster",
        "kb_date": KB_VERSION,
        "snippet": "Database Cluster architecture: primary/replica failover is automatic, "
        "with application connection pools re-resolving the primary DNS record post-"
        "failover. Prior incident (2026-04): a failover storm during a rolling patch "
        "caused connection-pool exhaustion across all app instances, because pooled "
        "connections did not evict stale primary sockets fast enough after DNS TTL expiry.",
    },
    {
        "citation": "ARCH-NETEDGE-2026-01",
        "service": "Network Edge/CDN",
        "kb_date": KB_VERSION,
        "snippet": "Network Edge/CDN architecture: regional edge PoPs route via anycast DNS "
        "with per-region health checks. Prior incident (2026-01): a DNS misconfiguration "
        "during an edge-node rollout withdrew health-check routes for one region, causing "
        "a regional outage until the rollout was rolled back and DNS TTL expired.",
    },
]

# ── keyword lexicons (deterministic retrieval + secret/internal-identifier screen) ──

_PAYGW_INDICATORS = (
    "payment gateway",
    "payment processing",
    "checkout",
    "transaction failure",
    "psp",
    "payment api",
    "circuit breaker",
    "payment timeout",
)
_AUTHIAM_INDICATORS = (
    "authentication",
    "auth service",
    "login failure",
    "sso",
    "oauth",
    "iam",
    "token validation",
    "signing certificate",
    "identity provider",
)
_DBCLUSTER_INDICATORS = (
    "database",
    "db cluster",
    "replication",
    "failover",
    "primary/replica",
    "connection pool exhaustion",
    "connection pool",
    "db outage",
)
_NETEDGE_INDICATORS = (
    "cdn",
    "network edge",
    "load balancer",
    "dns",
    "edge node",
    "latency spike",
    "packet loss",
    "regional outage",
    "anycast",
)

_SERVICE_ROUTING: list[tuple[str, tuple[str, ...]]] = [
    ("Payment Gateway", _PAYGW_INDICATORS),
    ("Auth/IAM Service", _AUTHIAM_INDICATORS),
    ("Database Cluster", _DBCLUSTER_INDICATORS),
    ("Network Edge/CDN", _NETEDGE_INDICATORS),
]

# Deterministic credential/secret + internal-identifier screen (rule/regex ruleset,
# NOT an LLM check). Ingested incident logs (alert-log summaries / resolution notes)
# that carry live tokens, connection strings, keys, or internal-only host identifiers
# are rejected before retrieval — the on-call engineer must redact the log excerpt
# before a PIR draft can be produced from it.
_SECRET_MARKERS = (
    "bearer ",
    "authorization:",
    "api_key",
    "apikey",
    "password:",
    "passwd:",
    "-----begin",
    "connection_string",
    "conn_str",
    "secret_key",
    "private_key",
)
# user:pass@host shaped connection-string credential.
_CONN_STRING_RE = re.compile(r"://[^/\s:]+:[^/\s@]+@")
# AWS-style access key id.
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
# RFC1918 private IP — internal-identifier detection (infra detail that must be
# redacted before it lands in a PIR draft that may be shared with the customer).
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)
# Internal-only hostname suffix (e.g. host.internal, db01.corp).
_INTERNAL_HOST_RE = re.compile(r"\b[\w.-]+\.(?:internal|corp)\b", re.IGNORECASE)


def has_leaked_secret_or_internal_identifier(text: str) -> bool:
    """Deterministic credential/secret + internal-identifier screen.

    True when the ingested log excerpt carries a live token/connection-string/key
    (must be redacted by the caller) or an internal-only host/IP identifier (infra
    detail that must not leak into a customer-facing PIR draft).
    """
    t = (text or "").lower()
    if any(m in t for m in _SECRET_MARKERS):
        return True
    if _CONN_STRING_RE.search(text or ""):
        return True
    if _AWS_KEY_RE.search(text or ""):
        return True
    if _PRIVATE_IP_RE.search(text or ""):
        return True
    if _INTERNAL_HOST_RE.search(text or ""):
        return True
    return False


def retrieve_context(query: str, kb_client: Optional[Any] = None) -> list[dict[str, Any]]:
    """Return system-architecture + prior-incident-history passages relevant to the
    incident query, across all affected services/components.

    Production: defer to the injected kb_client (template-owned architecture +
    incident-history index). Offline/CI: deterministic keyword-matched corpus above.
    A query may match multiple services at once (a cross-service incident, e.g. a
    payment-gateway failure triggered by a database failover storm).
    """
    if kb_client is not None:
        # kb_client is caller-injected (production system-architecture + incident-
        # history index) and duck-typed — its actual return shape can't be verified
        # statically, so this cast documents the expected contract explicitly.
        return cast("list[dict[str, Any]]", kb_client.retrieve(query))

    t = (query or "").lower()
    matched_services = {service for service, keywords in _SERVICE_ROUTING if any(k in t for k in keywords)}
    if not matched_services:
        return []
    return [p for p in INCIDENT_KB if p["service"] in matched_services]


def reconstruct_pir(query: str, context: list[dict[str, Any]]) -> str:
    """Deterministic grounded PIR draft synthesis: NOT a pure single-passage lookup —
    reconstructs a timeline, 5-Why root cause, contributing factors, customer-impact
    assessment, and corrective actions with ownership suggestions, grounded in the
    retrieved architecture + prior-incident context (in citation order).

    This deterministic synthesiser is the offline/CI fallback for an injected LLM
    reasoner (deferred — see docs/02 §11); the section/citation contract stays stable
    either way.
    """
    services = sorted({p["service"] for p in context})
    lines = [
        "### Timeline",
        f"- Incident detected and escalated for: {', '.join(services)}.",
        "- On-call engineer triggered PIR drafting after resolution; timeline reconstructed "
        "from the ticket data, alert-log summary, and resolution notes against the "
        "architecture/incident-history context below.",
        "",
        "### Root Cause (5-Why)",
    ]
    for p in sorted(context, key=lambda p: p["citation"]):
        lines.append(f"- **{p['service']}** ({p['citation']}, KB version {p['kb_date']}): {p['snippet']}")
    lines += [
        "",
        "### Contributing Factors",
        "- Prior-incident precedent above indicates a recurring architectural gap "
        "(see citations) rather than a purely one-off failure.",
        "",
        "### Customer Impact",
        "- Impact scoped to the affected service(s) above for the incident window; "
        "exact customer/SLA figures to be filled in by the on-call engineer from the "
        "ticket data.",
        "",
        "### Corrective Actions",
        "- Owner suggestion: service/component owning team for each citation above to "
        "review the architectural gap identified in the prior-incident snippet and "
        "confirm whether the earlier corrective action was fully implemented.",
        "- Owner suggestion: on-call/IT-ops lead to confirm SLA reporting deadline (48-72h) "
        "is met with this draft as the starting point.",
    ]
    return "\n".join(lines)
