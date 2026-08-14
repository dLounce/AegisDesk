from typing import Final

from pydantic import BaseModel, ConfigDict

from aegisdesk.agents.model import Model, ModelRequest
from aegisdesk.agents.state import RequestCategory, category_from_name
from aegisdesk.domain.enums import AgentName, RiskTier

# Which specialist owns each category. Total over RequestCategory and asserted so at import,
# so the mapping cannot silently miss a member and leave a request unroutable at runtime. The
# model influences the category (untrusted, validated to the enum); the app maps category to
# specialist deterministically, so a model never picks the route directly.
_TARGET_BY_CATEGORY: Final[dict[RequestCategory, AgentName]] = {
    RequestCategory.KB_QUESTION: AgentName.RESOLVER,
    RequestCategory.ROUTINE_SUPPORT: AgentName.RESOLVER,
    RequestCategory.ACCESS_REQUEST: AgentName.ESCALATION,
    RequestCategory.DESTRUCTIVE_ACCESS: AgentName.ESCALATION,
}

_RISK_BY_NAME: Final[dict[str, RiskTier]] = {r.value: r for r in RiskTier}

if set(_TARGET_BY_CATEGORY) != set(RequestCategory):
    raise AssertionError("every request category must map to a specialist")


# Raised when model output cannot be turned into a route. The reason travels to the audit
# trail; it never reaches the model, which sees one generic refusal.
class RoutingRefused(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RouteDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    target: AgentName
    category: RequestCategory
    risk_tier: RiskTier
    scope_changed: bool


# Classifies one message. Unknown category or risk fails closed: an unrecognised value is
# refused rather than defaulted to a route, because a permissive default is exactly what a
# malformed or manipulated model would exploit. The risk tier is advisory — it reaches a
# reviewer but the guard recomputes the authoritative tier — so a model choosing it cannot
# change authorization.
class Router:
    def __init__(self, model: Model) -> None:
        self._model = model

    def classify(self, message: str) -> RouteDecision:
        response = self._model.respond(ModelRequest(agent=AgentName.ROUTER, message=message))
        category = category_from_name(response.category)
        if category is None:
            raise RoutingRefused("unknown_category")
        risk_tier = _RISK_BY_NAME.get(response.risk)
        if risk_tier is None:
            raise RoutingRefused("unknown_risk")
        return RouteDecision(
            target=_TARGET_BY_CATEGORY[category],
            category=category,
            risk_tier=risk_tier,
            scope_changed=response.scope_changed,
        )
