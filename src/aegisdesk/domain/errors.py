class AegisDeskError(Exception):
    pass


# Subclasses ValueError so that a violation raised inside a Pydantic validator is collected
# into that model's ValidationError alongside ordinary field errors, while still being
# distinguishable as a domain invariant breach rather than a type or format problem.
class DomainInvariantError(AegisDeskError, ValueError):
    pass


class UnknownEmployeeError(AegisDeskError):
    pass


class UnknownResourceError(AegisDeskError):
    pass


# Raised whenever a requester asks for another employee's record, whether or not that
# employee exists. Reporting "unknown employee" for a non-existent target would turn the
# directory into a membership oracle.
class CrossEmployeeAccessError(AegisDeskError):
    pass
