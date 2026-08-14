from pydantic import BaseModel, ConfigDict

from aegisdesk.agents.model import Model, ModelRequest
from aegisdesk.agents.state import PRIVILEGED_CATEGORIES, category_from_name
from aegisdesk.backends.kb import KnowledgeBase
from aegisdesk.domain.enums import AgentName
from aegisdesk.prompting import ModelInput, assemble, render_kb_documents

# A routine answer the Resolver hands back. Deliberately plain text: the Resolver produces no
# action and touches no protected capability, so there is nothing here for the control plane
# to gate.
RESOLVER_KB_LIMIT = 3


class ResolverResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    answer: str


# The signal the Resolver raises instead of answering when a request it was handed is actually
# privileged. It stops the routine path rather than continuing it, which is the scope-change
# rule: the system never assumes a workflow stays low-risk because it started that way.
class ScopeChange(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str = "scope_change"


# Handles routine, knowledge-backed work. It has no guard, no access backend, and no protected
# capability, so there is no code path from here to access_api; the capability boundary is
# structural, not a prompt instruction. KB text reaches the model only through prompting.assemble,
# which places it in a DATA channel, so an instruction embedded in a document stays data.
class Resolver:
    def __init__(self, model: Model, kb: KnowledgeBase) -> None:
        self._model = model
        self._kb = kb

    def handle(self, message: str) -> ResolverResult | ScopeChange:
        response = self._model.respond(
            ModelRequest(
                agent=AgentName.RESOLVER,
                message=message,
                context=self._context(message),
            )
        )
        category = category_from_name(response.category)
        if response.scope_changed or (category is not None and category in PRIVILEGED_CATEGORIES):
            return ScopeChange()
        return ResolverResult(answer=response.answer)

    def _context(self, message: str) -> ModelInput:
        documents = self._kb.search(message, limit=RESOLVER_KB_LIMIT)
        return assemble(render_kb_documents(documents))
