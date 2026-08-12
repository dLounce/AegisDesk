from typing import NewType

# These provide static distinction only. NewType is an identity function at runtime, so
# ResourceId(some_employee_id) succeeds and survives any str round-trip, including
# checkpoint deserialisation. Format validation belongs at the boundaries where untrusted
# strings enter the system, not here.

EmployeeId = NewType("EmployeeId", str)
ReviewerId = NewType("ReviewerId", str)
ResourceId = NewType("ResourceId", str)
TicketId = NewType("TicketId", str)
WorkflowId = NewType("WorkflowId", str)
ActionId = NewType("ActionId", str)
ApprovalId = NewType("ApprovalId", str)
AuditEventId = NewType("AuditEventId", str)
PolicyVersion = NewType("PolicyVersion", str)

# Digest of the canonical serialisation of a proposed action's arguments. An approval binds
# to this value, and the resume path recomputes it, so a change to any argument between
# proposal and execution invalidates the approval.
ArgumentDigest = NewType("ArgumentDigest", str)
