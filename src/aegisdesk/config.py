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
