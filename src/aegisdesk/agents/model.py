from collections.abc import Mapping
from typing import Protocol

from pydantic import BaseModel, ConfigDict

from aegisdesk.domain.enums import AgentName
from aegisdesk.prompting import ModelInput


# What an agent hands to a model. `message` is untrusted employee text and `context` is the
# assembled instruction/DATA input (KB documents already demarcated by prompting.py). No
# identity, session, or authorization value is present: a model is never given the means to
# establish who is asking or what is permitted.
class ModelRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent: AgentName
    message: str
    context: ModelInput | None = None


# Everything a model is allowed to influence, and nothing else. Every field is untrusted: the
# agents validate each one against an enum or ignore it. The defaults fail safe — an unnamed
# category is unroutable and the advisory risk defaults to the highest tier — so a silent or
# malformed model cannot produce a permissive decision. `claimed_employee_id`, `approve`, and
# `wants_approval` exist precisely so the tests can prove the workflow ignores them: a model
# cannot name a requester, grant itself approval, or claim a prior one.
class ModelResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    category: str = "unknown"
    risk: str = "high"
    operation: str = ""
    resource_id: str = ""
    permission: str = ""
    duration: str = ""
    scope_changed: bool = False
    answer: str = ""
    claimed_employee_id: str = ""
    approve: bool = False
    wants_approval: bool = False


class Model(Protocol):
    def respond(self, request: ModelRequest) -> ModelResponse: ...


# A deterministic stand-in for a language model. It maps (agent, message) to a fixed response
# and returns a safe default for anything unscripted, so a scenario is reproducible and a run
# never depends on a network call or provider. DESIGN.md 8 requires this: agents driven by a
# scripted model make it possible to simulate a compromised agent by emitting exact output.
class ScriptedModel:
    def __init__(
        self,
        script: Mapping[tuple[AgentName, str], ModelResponse],
        default: ModelResponse | None = None,
    ) -> None:
        self._script = dict(script)
        self._default = default if default is not None else ModelResponse()

    def respond(self, request: ModelRequest) -> ModelResponse:
        return self._script.get((request.agent, request.message), self._default)
