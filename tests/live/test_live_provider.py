import pytest

from aegisdesk.agents.model import ModelRequest, ModelResponse
from aegisdesk.agents.providers import LiveModel, build_model
from aegisdesk.config import load_model_settings
from aegisdesk.domain.enums import AgentName

# Every test here is excluded from the default run by `-m 'not live'` (pyproject) and additionally
# skipped unless the environment actually selects and configures a live provider. It makes exactly
# one provider call, per NON_NEGOTIABLES §9 (minimise live calls, no unnecessary retries).
pytestmark = pytest.mark.live


def _live_model() -> LiveModel:
    settings = load_model_settings()
    if not settings.is_live:
        pytest.skip("AEGISDESK_MODEL_PROVIDER is not set to a live provider")
    try:
        settings.require_live()
    except Exception as error:  # noqa: BLE001 - surfaced as a skip, not a failure
        pytest.skip(f"live provider not fully configured: {error}")
    model = build_model(settings)
    assert isinstance(model, LiveModel)
    return model


def test_live_provider_returns_a_valid_response_object() -> None:
    model = _live_model()
    response = model.respond(
        ModelRequest(agent=AgentName.ROUTER, message="I need admin access to the production db")
    )
    # Whatever the provider says, the layer must yield a well-formed ModelResponse (a parsed one or
    # the fail-closed default) and record one telemetry entry.
    assert isinstance(response, ModelResponse)
    assert len(model.telemetry) == 1
    assert model.telemetry[0].latency_ms >= 0.0
