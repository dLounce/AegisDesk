import pytest

from aegisdesk.agents.model import ModelRequest, ModelResponse, ScriptedModel
from aegisdesk.agents.providers import (
    ChatReply,
    LiveModel,
    build_model,
)
from aegisdesk.config import ModelProvider, ModelSettings
from aegisdesk.domain.enums import AgentName
from aegisdesk.domain.ids import WorkflowId
from aegisdesk.evaluation.harness import Harness

ROUTER_REQUEST = ModelRequest(agent=AgentName.ROUTER, message="prod db admin")


# A deterministic stand-in for the transport: returns a fixed reply, so LiveModel can be exercised
# with no network and no provider SDK.
class _StubClient:
    def __init__(self, content: str, input_tokens: int = 11, output_tokens: int = 7) -> None:
        self._content = content
        self._input = input_tokens
        self._output = output_tokens

    def complete(self, system_prompt: str, user_message: str) -> ChatReply:
        return ChatReply(
            content=self._content, input_tokens=self._input, output_tokens=self._output
        )


class _RaisingClient:
    def __init__(self, error: Exception) -> None:
        self._error = error

    def complete(self, system_prompt: str, user_message: str) -> ChatReply:
        raise self._error


def test_valid_json_is_parsed_and_telemetry_recorded() -> None:
    model = LiveModel(_StubClient('{"category": "access_request", "risk": "high"}'))
    response = model.respond(ROUTER_REQUEST)
    assert response.category == "access_request"
    assert response.risk == "high"
    assert len(model.telemetry) == 1
    call = model.telemetry[0]
    assert call.ok is True
    assert call.input_tokens == 11
    assert call.output_tokens == 7
    assert call.latency_ms >= 0.0


def test_malformed_json_fails_closed_to_safe_default() -> None:
    model = LiveModel(_StubClient("not json at all"))
    response = model.respond(ROUTER_REQUEST)
    assert response == ModelResponse()
    assert response.category == "unknown"
    assert response.risk == "high"
    assert model.telemetry[0].ok is False


def test_extra_key_is_rejected_fail_closed() -> None:
    # ModelResponse forbids extra fields; a reply with an unknown key must not be trusted.
    model = LiveModel(_StubClient('{"category": "kb_question", "unexpected": "x"}'))
    assert model.respond(ROUTER_REQUEST) == ModelResponse()


def test_wrong_type_is_rejected_fail_closed() -> None:
    model = LiveModel(_StubClient('{"scope_changed": "not-a-bool"}'))
    assert model.respond(ROUTER_REQUEST) == ModelResponse()


@pytest.mark.parametrize(
    "error",
    [TimeoutError("provider timed out"), ConnectionError("reset"), RuntimeError("provider 500")],
)
def test_transport_failure_fails_closed_without_raising(error: Exception) -> None:
    model = LiveModel(_RaisingClient(error))
    response = model.respond(ROUTER_REQUEST)  # must not raise
    assert response == ModelResponse()
    call = model.telemetry[0]
    assert call.ok is False
    assert call.input_tokens == 0
    assert call.output_tokens == 0


def test_no_secret_or_message_body_is_used_as_authority_only_declared_fields() -> None:
    # A reply that declares approval and an identity parses those fields, but they are inert by
    # contract (the agents/guard ignore them). This asserts the model layer surfaces exactly the
    # declared response and invents nothing else.
    content = '{"approve": true, "claimed_employee_id": "E9999", "category": "kb_question"}'
    response = LiveModel(_StubClient(content)).respond(ROUTER_REQUEST)
    assert response.approve is True
    assert response.claimed_employee_id == "E9999"
    assert response.category == "kb_question"


def test_live_self_approval_and_identity_execute_nothing_through_the_workflow() -> None:
    # End-to-end containment of the live path: a model that claims an identity and self-approval
    # and asks for privileged access still cannot execute — the guard and approval gate are
    # independent of what the model says. Router and escalation calls get the same adversarial JSON.
    adversarial = (
        '{"category": "access_request", "risk": "high", "operation": "grant_access",'
        ' "resource_id": "prod-db", "permission": "admin", "duration": "eight_hours",'
        ' "approve": true, "claimed_employee_id": "E9999"}'
    )
    harness = Harness({}, model=LiveModel(_StubClient(adversarial)))
    result = harness.sup.handle("E1042", "prod db admin", WorkflowId("WF-LIVE"))
    assert harness.access.execution_count == 0
    assert not result.approval_id or harness.access.execution_count == 0


def test_factory_defaults_to_scripted_model() -> None:
    model = build_model(ModelSettings(provider=ModelProvider.SCRIPTED))
    assert isinstance(model, ScriptedModel)


def test_factory_uses_injected_scripted_factory() -> None:
    sentinel = ScriptedModel({})
    model = build_model(ModelSettings(provider=ModelProvider.SCRIPTED), lambda: sentinel)
    assert model is sentinel


def test_factory_live_without_config_fails_closed() -> None:
    from aegisdesk.config import ModelConfigError

    with pytest.raises(ModelConfigError):
        build_model(ModelSettings(provider=ModelProvider.OPENAI_COMPATIBLE))


def test_factory_live_with_config_builds_live_model(monkeypatch: pytest.MonkeyPatch) -> None:
    # The factory branch is what we assert here: a configured live provider yields a LiveModel, not
    # a ScriptedModel. The concrete transport is exercised by the gated live smoke test; here it is
    # replaced with a stub so the unit test needs no network client and no provider SDK.
    from aegisdesk.agents import providers

    monkeypatch.setattr(providers, "_build_openai_client", lambda settings: _StubClient("{}"))
    settings = ModelSettings(
        provider=ModelProvider.OPENAI_COMPATIBLE,
        model_name="gpt-4o-mini",
        api_key="sk-only-presence-checked",  # type: ignore[arg-type]
    )
    model = build_model(settings)
    assert isinstance(model, LiveModel)
