import hmac
import secrets
from datetime import timedelta
from typing import Final

from aegisdesk.domain.access import AccessGrant, ExecutionReceipt
from aegisdesk.domain.enums import DURATION_MAX_HOURS
from aegisdesk.domain.errors import ProtectedExecutionError
from aegisdesk.domain.ids import ActionId

# One message for a missing receipt and for an unminted one alike. Both mean the caller did not
# come through the guard, and separating them would say which half of the check failed.
_NOT_MINTED: Final = "protected execution requires a receipt minted by the runtime guard"


class AccessBackend:
    def __init__(self) -> None:
        self._grants: dict[ActionId, AccessGrant] = {}
        # Generated per instance rather than declared at module level, so the value cannot be
        # obtained by importing anything.
        self._minting_key = secrets.token_urlsafe(32)
        self._claimed = False

    # The backend accepts one minting authority for its lifetime, and the first caller to claim
    # it becomes that authority. A second claim is refused, so a component loading later cannot
    # acquire the ability to mint a receipt merely by asking for it, and a receipt built by any
    # other caller is refused below for want of the key.
    def claim_minting_authority(self) -> str:
        if self._claimed:
            raise ProtectedExecutionError("the access backend already has a minting authority")
        self._claimed = True
        return self._minting_key

    # Keyed on the action identifier, which is derived from the action itself, so a retried
    # execution of one authorised action returns the grant that already exists instead of
    # issuing a second. This is deterministic idempotency at one boundary, not a distributed
    # exactly-once guarantee: it holds for repeated calls against this store and says nothing
    # about two stores or two processes.
    def grant(self, receipt: ExecutionReceipt, minting_key: str) -> AccessGrant:
        if not isinstance(receipt, ExecutionReceipt) or not isinstance(minting_key, str):
            raise ProtectedExecutionError(_NOT_MINTED)
        # Compared as bytes so that a non-ASCII candidate is refused rather than raising, and
        # in constant time so that a caller cannot recover the key one character at a time.
        if not hmac.compare_digest(minting_key.encode("utf-8"), self._minting_key.encode("utf-8")):
            raise ProtectedExecutionError(_NOT_MINTED)

        existing = self._grants.get(receipt.action_id)
        if existing is not None:
            return existing

        hours = DURATION_MAX_HOURS[receipt.duration]
        issued = AccessGrant(
            employee_id=receipt.requester_id,
            resource_id=receipt.resource_id,
            permission=receipt.permission,
            duration=receipt.duration,
            granted_at=receipt.authorised_at,
            expires_at=None if hours is None else receipt.authorised_at + timedelta(hours=hours),
            granted_via_action_id=receipt.action_id,
        )
        self._grants[receipt.action_id] = issued
        return issued

    def grant_for(self, action_id: ActionId) -> AccessGrant | None:
        return self._grants.get(action_id)
