# SVC-C2-101 — Managed IT Services Incident Post-Mortem Draft Agent

> **Category**: Cat 2 (domain workflow — business logic in src/)
> **Industry**: Services

## Overview

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

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent raises
`PlatformRequired` during graph compile / start-up preflight rather than starting in a partially
working state. This is intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, services, schemas)
tests/        unit, integration and boundary tests
config/       agent configuration
docs/         design and operational documentation
```

See `docs/` for the design spec and test specification.

## Customising

1. Adjust `config/` for your own environment and policies.
2. Replace the knowledge sources and sample data with your own.
3. Review the node implementations under `src/nodes/` for domain-specific logic.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.

