import random
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from aegisdesk.agents.state import InformationSlot, WorkflowPhase

# The simulated employee (S18). It is the untrusted actor the evaluation exercises, not a component
# of the system: it produces exactly what a real employee produces — a claimed identifier and a
# message — and nothing else. It is deliberately NOT the agents' Model protocol. The Model shapes a
# control-plane decision (ModelResponse); the employee is the party under test, and giving it the
# Model seam would blur the trust boundary S18 exists to measure.
#
# Everything here is declarative evaluation data. Like Scenario, a Persona carries no reference to
# the guard, the access backend, the approval store, or the minting key, and a SimulatedEmployee is
# handed none of them either. The runner mediates: it feeds the employee a minimal, structured
# observation and replays the (claimed_id, message) it returns through the real Supervisor, which
# treats that message as untrusted input exactly as it treats a live employee's (agent-security
# F1/F3, DESIGN AD-53).


class PersonaStyle(Enum):
    TERSE = "terse"
    VERBOSE = "verbose"
    URGENT = "urgent"


# The minimum safe projection of a paused turn the employee needs to continue the conversation.
# It carries only structured workflow signals — the phase and which information slots are still
# missing — and deliberately NO agent- or model-authored prose. Exposing internal response text
# here would open a channel through which the system's own output could become an instruction to the
# simulated user; the seam is kept to enums and enum tuples so no such channel exists (S18 design
# correction). A SeededPersonaEmployee reacts to `missing_information` alone; it never reads agent
# text, which is why none is provided.
@dataclass(frozen=True)
class EmployeeObservation:
    phase: WorkflowPhase
    missing_information: tuple[InformationSlot, ...] = ()


# One line of the realized conversation, recorded for diagnostics. `identifier` is a claimed
# employee id or a reviewer id — a label the runner echoes, never an authority: identity is still
# established by the session against the directory. Diagnostic only; the runner keeps it in memory
# and it is never serialized into the committed §20 baseline artifact.
@dataclass(frozen=True)
class TranscriptEntry:
    actor: str
    identifier: str
    content: str


# What the runner drives the employee side of a scenario with. `opening` starts the conversation;
# `reply` is called only while the workflow is paused for information and returns the next
# (claimed_id, message), or None to stop talking (which lets the workflow fail closed rather than
# loop). The return shape is identical to a scripted EmployeeTurn: a simulated employee can do
# nothing a static turn could not — it only generates that same untrusted data dynamically.
class SimulatedEmployee(Protocol):
    def opening(self) -> tuple[str, str]: ...

    def reply(self, observation: EmployeeObservation) -> tuple[str, str] | None: ...


# A persona: declarative, evaluation-only description of how a simulated employee behaves. Its
# `claimed_id` is a CLAIM the session authenticates against the directory — never authority — so a
# persona asserting a privileged or foreign identity gains nothing (identity invariant). Candidate
# phrasings are tuples so a seed can select among them: identical seed reproduces the exact
# sequence, and sweeping the seed yields different-but-reproducible input, which is the stochastic
# variance later repeated-run (pass^k) evaluation consumes. No control-plane handle appears here.
@dataclass(frozen=True)
class Persona:
    id: str
    claimed_id: str
    openings: tuple[str, ...]
    slot_replies: Mapping[InformationSlot, tuple[str, ...]] = field(default_factory=dict)
    style: PersonaStyle = PersonaStyle.TERSE
    seed: int = 0
    goal: str = ""

    def __post_init__(self) -> None:
        if not self.openings:
            raise ValueError("a persona needs at least one opening message")
        if any(not choices for choices in self.slot_replies.values()):
            raise ValueError("a persona slot reply must offer at least one phrasing")


# The deterministic default simulated employee. A fresh instance seeds its own random.Random from
# the persona, so — because the runner builds a fresh employee per run (mirroring the fresh model
# and harness, agent-security F5) — the same seed reproduces the same messages every run, while a
# different seed varies them reproducibly. It holds only the persona (data); it is never given a
# control-plane handle, and it can emit no reviewer decision or approval — its only outputs are the
# (claimed_id, message) pairs a real employee would send.
class SeededPersonaEmployee:
    def __init__(self, persona: Persona) -> None:
        self._persona = persona
        self._rng = random.Random(persona.seed)

    def opening(self) -> tuple[str, str]:
        return self._persona.claimed_id, self._rng.choice(self._persona.openings)

    def reply(self, observation: EmployeeObservation) -> tuple[str, str] | None:
        # Only ever speaks up to supply information the workflow is explicitly waiting on. Anything
        # else (a terminal phase, or a pause for a slot it has no answer for) ends its turn, so a
        # persona that cannot satisfy a request stops rather than looping.
        if observation.phase is not WorkflowPhase.AWAITING_INFO:
            return None
        for slot in observation.missing_information:
            choices = self._persona.slot_replies.get(slot)
            if choices:
                return self._persona.claimed_id, self._rng.choice(choices)
        return None
