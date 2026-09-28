"""AgentCore Platform v1.0"""

# SVC-C2-101 — Managed IT Services Incident Post-Mortem Draft Agent (VectorRAG node-backbone)
#
# Cat 2 — Multi-step domain workflow (job-to-be-done).
#   Parent  : AgentBaseGraph (outer graph, L1 direct).
#   Pipeline: START → initialize → pre_process → main → post_process → finalize → END
#   Pattern : VectorRAG (system-architecture + prior-incident-history grounded PIR draft
#             synthesis).
#
#   pre_process  — InputValidate + CredentialSecretScreen: sanitise · S-2 gate ·
#                  deterministic live-credential/internal-identifier reject
#   main         — ContextRetrieve + RootCauseReconstruct (VectorRAG over the
#                  system-architecture + prior-incident-history KB)
#   post_process — PIRAssemble + OutputValidate(S-3 structural + grounding gate) +
#                  IncidentAudit (S-4)
#
# The system-architecture + prior-incident-history kb_client is injected via graph
# config at register_nodes() time; absent → deterministic CI-safe fallback corpus
# (services.service). No live API at query time; no runtime/user memory or shared KG.

from framework.graph.agent_base_graph import AgentBaseGraph

from src.nodes.main_node import MainNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State


class Graph(AgentBaseGraph):
    """Cat 2 outer graph for SVC-C2-101.

    Backbone: initialize → pre_process → main → post_process → finalize (fixed).
    Class name matches config/agent.yaml `class:` exactly.
    """

    @property
    def name(self) -> str:
        return "svc_c2_101"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        super().register_nodes()  # injects InitializeNode + FinalizeNode

        cfg = getattr(self, "config", None) or {}
        kb_client = cfg.get("kb_client")

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = MainNode(kb_client=kb_client)
        self._nodes["post_process"] = PostProcessNode()

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.
