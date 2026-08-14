import pytest

from aegisdesk.config import (
    ModelConfigError,
    ModelProvider,
    ModelSettings,
    load_model_settings,
)

_ALL_KEY_ENV = (
    "AEGISDESK_MODEL_PROVIDER",
    "AEGISDESK_MODEL_NAME",
    "AEGISDESK_MODEL_BASE_URL",
    "AEGISDESK_MODEL_API_KEY",
    "AEGISDESK_MODEL_TIMEOUT_SECONDS",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
)


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ALL_KEY_ENV:
        monkeypatch.delenv(name, raising=False)


def test_default_provider_is_scripted_and_not_live() -> None:
    settings = ModelSettings()
    assert settings.provider is ModelProvider.SCRIPTED
    assert settings.is_live is False


def test_openai_compatible_provider_is_live(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISDESK_MODEL_PROVIDER", "openai_compatible")
    assert ModelSettings().is_live is True


def test_unknown_provider_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISDESK_MODEL_PROVIDER", "anthropic-ish")
    with pytest.raises(ModelConfigError):
        load_model_settings()


def test_require_live_raises_when_model_name_and_key_absent() -> None:
    with pytest.raises(ModelConfigError) as excinfo:
        ModelSettings(provider=ModelProvider.OPENAI_COMPATIBLE).require_live()
    message = str(excinfo.value)
    assert "AEGISDESK_MODEL_NAME" in message
    assert "model API key" in message


def test_require_live_message_never_contains_the_key_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGISDESK_MODEL_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGISDESK_MODEL_API_KEY", "sk-super-secret-value")
    # Model name is still missing, so require_live raises — and must not echo the key it did find.
    with pytest.raises(ModelConfigError) as excinfo:
        load_model_settings().require_live()
    assert "sk-super-secret-value" not in str(excinfo.value)


def test_require_live_passes_when_fully_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISDESK_MODEL_PROVIDER", "openai_compatible")
    monkeypatch.setenv("AEGISDESK_MODEL_NAME", "gpt-4o-mini")
    monkeypatch.setenv("AEGISDESK_MODEL_API_KEY", "sk-x")
    load_model_settings().require_live()  # does not raise


def _secret(settings: ModelSettings) -> str:
    key = settings.api_key
    assert key is not None
    return key.get_secret_value()


def test_api_key_falls_back_to_openai_then_openrouter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-router")
    assert _secret(ModelSettings()) == "sk-router"
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
    assert _secret(ModelSettings()) == "sk-openai"
    monkeypatch.setenv("AEGISDESK_MODEL_API_KEY", "sk-neutral")
    assert _secret(ModelSettings()) == "sk-neutral"


def test_secret_key_does_not_leak_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISDESK_MODEL_API_KEY", "sk-do-not-print")
    settings = ModelSettings()
    assert "sk-do-not-print" not in repr(settings)
    assert "sk-do-not-print" not in str(settings)
