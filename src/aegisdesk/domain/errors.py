class AegisDeskError(Exception):
    pass


# Subclasses ValueError so that a violation raised inside a Pydantic validator is collected
# into that model's ValidationError alongside ordinary field errors, while still being
# distinguishable as a domain invariant breach rather than a type or format problem.
class DomainInvariantError(AegisDeskError, ValueError):
    pass
