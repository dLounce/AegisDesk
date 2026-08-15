from enum import Enum

from pydantic import AliasChoices, Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


# Which model implementation the factory builds. SCRIPTED is the deterministic default used by
# every unit test and local run; OPENAI_COMPATIBLE selects the live provider. A plain Enum for
# the reason enums.py gives every selector: a raw string must not satisfy the check by itself.
class ModelProvider(Enum):
    SCRIPTED = "scripted"
    OPENAI_COMPATIBLE = "openai_compatible"


# Raised when the environment selects a live provider but the configuration needed to build it is
# incomplete. The message names the missing field, never the secret value.
class ModelConfigError(Exception):
    pass


# Configuration for the model layer, read from process environment only (no .env file is loaded,
# so a test process never inherits a developer's real credentials implicitly). The API key is a
# SecretStr so it never renders in a repr, log line, or exception; nothing else in this module or
# the provider ever converts it back to a string except the one call that hands it to the client.
class ModelSettings(BaseSettings):
    # populate_by_name lets the fields be set by their Python name (direct construction, e.g. in
    # tests and the factory) in addition to their environment validation_alias, so unit
    # construction and environment-driven construction resolve identically.
    model_config = SettingsConfigDict(extra="ignore", frozen=True, populate_by_name=True)

    provider: ModelProvider = Field(
        default=ModelProvider.SCRIPTED,
        validation_alias="AEGISDESK_MODEL_PROVIDER",
    )
    model_name: str = Field(default="", validation_alias="AEGISDESK_MODEL_NAME")
    base_url: str | None = Field(default=None, validation_alias="AEGISDESK_MODEL_BASE_URL")
    # Read from the neutral name first, then the two provider-specific names already documented in
    # .env.example, so an existing OpenAI/OpenRouter key works without a rename.
    api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "AEGISDESK_MODEL_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"
        ),
    )
    timeout_seconds: float = Field(default=30.0, validation_alias="AEGISDESK_MODEL_TIMEOUT_SECONDS")

    @property
    def is_live(self) -> bool:
        return self.provider is ModelProvider.OPENAI_COMPATIBLE

    # Fails closed on incomplete live configuration: a live provider with no model name or no key
    # cannot be built, and the request is refused at construction rather than at first call. The
    # key's presence is checked, never its value; the value is never placed in the message.
    def require_live(self) -> None:
        missing = [
            name
            for name, present in (
                ("AEGISDESK_MODEL_NAME", bool(self.model_name.strip())),
                ("model API key", self.api_key is not None),
            )
            if not present
        ]
        if missing:
            raise ModelConfigError(
                "live model provider missing configuration: " + ", ".join(missing)
            )


def load_model_settings() -> ModelSettings:
    try:
        return ModelSettings()
    except ValidationError as error:
        # An unknown provider value (or malformed setting) fails closed as a config error without
        # echoing the offending environment, which could contain a secret.
        raise ModelConfigError("invalid model configuration") from error


# Configuration for the simulated-employee model (S20), read from its own AEGISDESK_PERSONA_MODEL_*
# environment namespace and deliberately kept independent of ModelSettings. The employee model is
# the evaluation harness, not the system under test: giving it a shared config would let one change
# silently alter both the measurer and the measured. It carries the same fail-closed provider
# selection as ModelSettings plus a sampling `temperature` — the S20 stochasticity knob. A nonzero
# default configures stochastic sampling; it is an experiment setting, not a guarantee that two
# calls differ.
class PersonaModelSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True, populate_by_name=True)

    provider: ModelProvider = Field(
        default=ModelProvider.SCRIPTED,
        validation_alias="AEGISDESK_PERSONA_MODEL_PROVIDER",
    )
    model_name: str = Field(default="", validation_alias="AEGISDESK_PERSONA_MODEL_NAME")
    base_url: str | None = Field(default=None, validation_alias="AEGISDESK_PERSONA_MODEL_BASE_URL")
    # Persona-specific key first, then the shared provider keys, but never AEGISDESK_MODEL_API_KEY:
    # the persona credential stays independent of the agent model's credential.
    api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "AEGISDESK_PERSONA_MODEL_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"
        ),
    )
    timeout_seconds: float = Field(
        default=30.0, validation_alias="AEGISDESK_PERSONA_MODEL_TIMEOUT_SECONDS"
    )
    # Nonzero by default so the employee model samples stochastically (the S20 experiment
    # variance source). Configurable; treated as experiment configuration, not a determinism claim.
    temperature: float = Field(default=0.9, validation_alias="AEGISDESK_PERSONA_MODEL_TEMPERATURE")

    @property
    def is_live(self) -> bool:
        return self.provider is ModelProvider.OPENAI_COMPATIBLE

    def require_live(self) -> None:
        missing = [
            name
            for name, present in (
                ("AEGISDESK_PERSONA_MODEL_NAME", bool(self.model_name.strip())),
                ("persona model API key", self.api_key is not None),
            )
            if not present
        ]
        if missing:
            raise ModelConfigError(
                "live persona model provider missing configuration: " + ", ".join(missing)
            )


def load_persona_model_settings() -> PersonaModelSettings:
    try:
        return PersonaModelSettings()
    except ValidationError as error:
        raise ModelConfigError("invalid persona model configuration") from error
