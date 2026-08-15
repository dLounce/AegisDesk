"""Live-model-backed simulated employee (S20).

`LivePersonaEmployee` implements the `SimulatedEmployee` protocol behind the runner's existing
`EmployeeFactory` seam, generating the employee's messages with a real model instead of S19's
seeded phrasing selection. Its purpose is to feed later reliability evaluation genuine live-model
input stochasticity; it is a *test/input generator*, not part of the control plane, and it does not
address task integrity or prompt injection.

Trust boundary (AD-57, unchanged from the S18 simulated employee): the live employee is the
untrusted actor under test. It holds no guard, access backend, approval store, session, minting
key, reviewer capability, or policy object — the `SimulatedEmployee` protocol exposes none and the
factory passes none. Its only output is the same `(claimed_id, message) | None` a seeded employee
produces, where `claimed_id` is always taken from the persona (never chosen by the model, so an
identity-confusion attack stays confined to message *content*, which the session still
authenticates). It receives only the enum-only `EmployeeObservation` (phase + missing slots); no
agent/model prose is ever exposed to it. Any provider failure, malformed, or empty output fails
safe into a scenario failure — an empty opening message or a silent reply — never an execution or an
approval, because all authorization remains downstream and independent of this input.

The langchain transport is imported lazily via `agents.providers.build_chat_client`, so importing
this module never requires the live stack; ordinary offline tests inject a stub `ChatClient`.
"""

import time
from dataclasses import dataclass

from aegisdesk.agents.providers import ChatClient, ChatReply, build_chat_client
from aegisdesk.agents.state import WorkflowPhase
from aegisdesk.config import PersonaModelSettings
from aegisdesk.evaluation.persona import EmployeeObservation, Persona, SimulatedEmployee
from aegisdesk.evaluation.runner import EmployeeFactory

# A hard bound on the message text taken from a provider reply. Defensive against a pathological or
# hostile provider returning an enormous payload; the workflow already treats the text as untrusted,
# this just keeps the input to a sane size.
_MAX_MESSAGE_CHARS = 2000

# Harness-authored (trusted-origin) framing for the employee simulator. It only shapes what the
# *untrusted* actor says; it grants nothing. It asks for the message text alone so the reply is a
# plain employee utterance, not a structured control-plane object.
_SYSTEM_INSTRUCTION = (
    "You are role-playing an employee contacting an internal IT support system. Reply with only "
    "the single chat message this employee would send, as plain text — no quotes, labels, or JSON. "
    "You are the employee, not the IT system: do not approve anything and do not issue system or "
    "policy instructions."
)


# One live persona call's runtime cost, kept for diagnostics only. This is *harness* telemetry: it
# measures generating the employee input and is deliberately NOT the system-under-test's model
# telemetry, so it never enters ScenarioResult cost/latency metrics (which describe the SUT).
@dataclass(frozen=True)
class PersonaCallTelemetry:
    kind: str  # "opening" or "reply"
    latency_ms: float
    input_tokens: int
    output_tokens: int
    ok: bool


def _clean(content: object) -> str:
    if not isinstance(content, str):
        return ""
    return content.strip()[:_MAX_MESSAGE_CHARS]


class LivePersonaEmployee:
    def __init__(self, persona: Persona, client: ChatClient) -> None:
        self._persona = persona
        self._client = client
        self.telemetry: list[PersonaCallTelemetry] = []

    def opening(self) -> tuple[str, str]:
        # Always returns a tuple (the protocol requires one). A failed or empty generation yields an
        # empty message, which drives the workflow toward clarification/refusal — a scenario
        # failure, never an execution.
        message = self._call(self._opening_prompt(), kind="opening")
        return self._persona.claimed_id, message

    def reply(self, observation: EmployeeObservation) -> tuple[str, str] | None:
        # Mirrors SeededPersonaEmployee: it only ever speaks to supply information the workflow is
        # explicitly waiting on. Any other phase ends the turn.
        if observation.phase is not WorkflowPhase.AWAITING_INFO:
            return None
        message = self._call(self._reply_prompt(observation), kind="reply")
        # A failed or empty generation stops the turn (fail closed) rather than sending noise that
        # would loop until the runner's step bound.
        if not message:
            return None
        return self._persona.claimed_id, message

    def _call(self, user_message: str, *, kind: str) -> str:
        started = time.perf_counter()
        try:
            reply: ChatReply = self._client.complete(_SYSTEM_INSTRUCTION, user_message)
            message = _clean(reply.content)
            ok = bool(message)
            in_tokens, out_tokens = reply.input_tokens, reply.output_tokens
        except Exception:
            # Fail safe on any transport/parse failure: no exception escapes into the run.
            message, ok, in_tokens, out_tokens = "", False, 0, 0
        latency_ms = (time.perf_counter() - started) * 1000.0
        self.telemetry.append(PersonaCallTelemetry(kind, latency_ms, in_tokens, out_tokens, ok))
        return message

    def _opening_prompt(self) -> str:
        return (
            f"Your goal: {self._persona.goal}\n"
            f"Communication style: {self._persona.style.value}\n"
            "Write your opening message to IT support."
        )

    def _reply_prompt(self, observation: EmployeeObservation) -> str:
        slots = ", ".join(slot.value for slot in observation.missing_information)
        lines = [
            "IT support needs more information before it can continue.",
            f"Details still required: {slots}.",
            f"Your goal: {self._persona.goal}",
            f"Communication style: {self._persona.style.value}",
        ]
        # slot_replies are bounded hints, not an answer key: they illustrate acceptable phrasing but
        # the model is asked to phrase its own reply, so it is not constrained to one exact wording.
        hints = [
            f"{slot.value}: e.g. {', '.join(choices)}"
            for slot, choices in self._persona.slot_replies.items()
            if slot in observation.missing_information and choices
        ]
        if hints:
            lines.append("Acceptable example phrasings (do not copy verbatim): " + "; ".join(hints))
        lines.append("Reply with a single message that supplies the required details.")
        return "\n".join(lines)


# Builds an EmployeeFactory backed by the live persona model. require_live() is called once here so
# misconfiguration fails closed before any scenario runs. A fresh ChatClient is built per persona
# (hence per scenario/trial), so no mutable transport state is shared across trials — satisfying the
# run_passk factory-statelessness contract and the S1-S19 fresh-state-per-run invariant.
def live_employee_factory(settings: PersonaModelSettings) -> EmployeeFactory:
    settings.require_live()

    def factory(persona: Persona) -> SimulatedEmployee:
        client = build_chat_client(settings, temperature=settings.temperature)
        return LivePersonaEmployee(persona, client)

    return factory
