import pytest

from aegisdesk.config import load_persona_model_settings
from aegisdesk.evaluation.live_persona import LivePersonaEmployee, live_employee_factory
from aegisdesk.evaluation.persona import Persona, PersonaStyle

# Excluded from the default run by `-m 'not live'` (pyproject) and additionally skipped unless the
# environment actually selects and configures a live persona provider. It makes exactly one provider
# call (opening only), per NON_NEGOTIABLES §9 (minimise live calls, no unnecessary retries).
pytestmark = pytest.mark.live


def _persona() -> Persona:
    return Persona(
        id="live_smoke",
        claimed_id="E1042",
        openings=("unused seed opening",),
        goal="ask IT to reset your VPN because it will not connect",
        style=PersonaStyle.TERSE,
    )


def test_live_persona_opening_returns_claimed_id_and_text() -> None:
    settings = load_persona_model_settings()
    if not settings.is_live:
        pytest.skip("AEGISDESK_PERSONA_MODEL_PROVIDER is not set to a live provider")
    try:
        settings.require_live()
    except Exception as error:  # noqa: BLE001 - surfaced as a skip, not a failure
        pytest.skip(f"live persona provider not fully configured: {error}")

    persona = _persona()
    employee = live_employee_factory(settings)(persona)
    assert isinstance(employee, LivePersonaEmployee)

    claimed_id, message = employee.opening()
    # The identity field is always the persona's, whatever the model returned; the message is
    # whatever text the provider produced (possibly empty on a failure — still a valid, safe shape).
    assert claimed_id == persona.claimed_id
    assert isinstance(message, str)
    assert len(employee.telemetry) == 1
    assert employee.telemetry[0].latency_ms >= 0.0
