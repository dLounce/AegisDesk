import hmac
import secrets
from collections.abc import Callable
from datetime import timedelta
from typing import Final

from aegisdesk.domain.access import AccessChange, AccessGrant, DestructiveReceipt, ExecutionReceipt
from aegisdesk.domain.enums import DURATION_MAX_HOURS, Permission, ProtectedOperation
from aegisdesk.domain.errors import (
    CurrentAccessMismatchError,
    NoCurrentAccessError,
    ProtectedExecutionError,
    UncertainDestructiveReplayError,
)
from aegisdesk.domain.ids import ActionId, EmployeeId, ResourceId

# One message for a missing receipt and for an unminted one alike. Both mean the caller did not
# come through the guard, and separating them would say which half of the check failed.
_NOT_MINTED: Final = "protected execution requires a receipt minted by the runtime guard"
_CURRENT_MISMATCH: Final = "the permission to revoke is not the one currently held"
_NO_CURRENT_ACCESS: Final = "no current access exists to modify"
_UNCERTAIN_REPLAY: Final = "a destructive operation with an uncertain outcome is not replayed"


class AccessBackend:
    def __init__(self) -> None:
        self._grants: dict[ActionId, AccessGrant] = {}
        # The authoritative record of what access is currently issued, keyed on the pair a grant,
        # a revoke and a modify all act on. A grant sets it, a revoke removes it and a modify
        # re-points it, so "what does this employee hold on this resource" is answerable here
        # rather than reconstructed from the grant log (S10 decision 3). No separate current-access
        # corpus exists, and baseline access is not consulted.
        self._current: dict[tuple[EmployeeId, ResourceId], Permission] = {}
        # The destructive-operation ledger. A completed change is returned again on replay, so a
        # retried destructive execution stays exactly-once; an action still in _attempted had a
        # first attempt that did not confirm completion, and is refused rather than retried
        # (S10 decision 9). This is deterministic idempotency at one boundary, not a distributed
        # exactly-once guarantee.
        self._completed: dict[ActionId, AccessChange] = {}
        self._attempted: set[ActionId] = set()
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
        if not isinstance(receipt, ExecutionReceipt):
            raise ProtectedExecutionError(_NOT_MINTED)
        self._require_minting_key(minting_key)

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
        # A grant issues current access, which is what a later revoke or modify acts on.
        self._current[receipt.requester_id, receipt.resource_id] = receipt.permission
        return issued

    def grant_for(self, action_id: ActionId) -> AccessGrant | None:
        return self._grants.get(action_id)

    # The smallest read a destructive operation needs: the permission this employee currently
    # holds on this resource, or None. It is the authoritative current-access source the revoke
    # and modify preconditions below check against.
    def get_current_permission(
        self, employee_id: EmployeeId, resource_id: ResourceId
    ) -> Permission | None:
        return self._current.get((employee_id, resource_id))

    # Removes the named permission. Requires that exact permission to be the one currently held,
    # so a revoke naming a permission the employee does not hold is refused rather than treated as
    # a no-op. The ledger makes a completed revoke return its recorded change on replay and an
    # uncertain one refuse.
    def revoke(self, receipt: DestructiveReceipt, minting_key: str) -> AccessChange:
        recorded = self._begin_destructive(receipt, minting_key, ProtectedOperation.REVOKE_ACCESS)
        if recorded is not None:
            return recorded
        key = (receipt.requester_id, receipt.resource_id)
        current = self._current.get(key)
        if current is None or current != receipt.permission:
            raise CurrentAccessMismatchError(_CURRENT_MISMATCH)
        change = AccessChange(
            operation=ProtectedOperation.REVOKE_ACCESS,
            employee_id=receipt.requester_id,
            resource_id=receipt.resource_id,
            previous_permission=current,
            resulting_permission=None,
            changed_at=receipt.authorised_at,
            changed_via_action_id=receipt.action_id,
        )
        return self._perform(receipt, lambda: self._apply_revoke(key), change)

    # Re-points existing access to the target permission. Requires that some access currently
    # exist, and records the permission held before the change alongside the one after it.
    def modify(self, receipt: DestructiveReceipt, minting_key: str) -> AccessChange:
        recorded = self._begin_destructive(
            receipt, minting_key, ProtectedOperation.MODIFY_PERMISSIONS
        )
        if recorded is not None:
            return recorded
        key = (receipt.requester_id, receipt.resource_id)
        current = self._current.get(key)
        if current is None:
            raise NoCurrentAccessError(_NO_CURRENT_ACCESS)
        change = AccessChange(
            operation=ProtectedOperation.MODIFY_PERMISSIONS,
            employee_id=receipt.requester_id,
            resource_id=receipt.resource_id,
            previous_permission=current,
            resulting_permission=receipt.permission,
            changed_at=receipt.authorised_at,
            changed_via_action_id=receipt.action_id,
        )
        return self._perform(receipt, lambda: self._apply_modify(key, receipt.permission), change)

    # Shared prologue for a destructive operation, run before any precondition check so a clean
    # refusal never marks the action attempted. Validates the receipt and the minting key, returns
    # the recorded change for a completed replay, and refuses an uncertain replay. Returns None
    # for a fresh attempt, which the caller then checks the operation's precondition for.
    def _begin_destructive(
        self, receipt: DestructiveReceipt, minting_key: str, operation: ProtectedOperation
    ) -> AccessChange | None:
        if not isinstance(receipt, DestructiveReceipt) or receipt.operation is not operation:
            raise ProtectedExecutionError(_NOT_MINTED)
        self._require_minting_key(minting_key)
        recorded = self._completed.get(receipt.action_id)
        if recorded is not None:
            return recorded
        if receipt.action_id in self._attempted:
            raise UncertainDestructiveReplayError(_UNCERTAIN_REPLAY)
        return None

    # The action is marked attempted immediately before the side effect and cleared only once the
    # change is recorded. If the side effect raises, the action stays attempted with no recorded
    # change — the uncertain state a replay refuses rather than retries.
    def _perform(
        self, receipt: DestructiveReceipt, apply: Callable[[], None], change: AccessChange
    ) -> AccessChange:
        self._attempted.add(receipt.action_id)
        apply()
        self._completed[receipt.action_id] = change
        self._attempted.discard(receipt.action_id)
        return change

    # Isolated so the side effect can be exercised as failing.
    def _apply_revoke(self, key: tuple[EmployeeId, ResourceId]) -> None:
        self._current.pop(key, None)

    def _apply_modify(self, key: tuple[EmployeeId, ResourceId], permission: Permission) -> None:
        self._current[key] = permission

    def _require_minting_key(self, minting_key: str) -> None:
        # Compared as bytes so that a non-ASCII candidate is refused rather than raising, and
        # in constant time so that a caller cannot recover the key one character at a time.
        if not isinstance(minting_key, str) or not hmac.compare_digest(
            minting_key.encode("utf-8"), self._minting_key.encode("utf-8")
        ):
            raise ProtectedExecutionError(_NOT_MINTED)
