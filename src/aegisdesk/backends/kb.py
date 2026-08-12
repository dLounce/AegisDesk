import re
from collections.abc import Iterable, Sequence

from pydantic import BaseModel, ConfigDict

MAX_SEARCH_LIMIT = 10
MAX_QUERY_LENGTH = 500

# A flat character class with a single quantifier: linear time, no backtracking, so an
# adversarial query cannot turn tokenisation into a denial of service.
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN_PATTERN.findall(text.lower()))


class KbDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    document_id: str
    title: str
    # Untrusted. Knowledge-base text is authored outside this system and may contain
    # instructions aimed at whatever reads it. It is returned verbatim and stays a field on
    # a record rather than a loose string, so a caller has to reach for it deliberately.
    # Demarcating it as data belongs to the layer that builds a prompt, not here.
    body: str


class KnowledgeBase:
    def __init__(self, documents: Iterable[KbDocument]) -> None:
        self._documents = tuple(documents)

    # Deterministic lexical scoring rather than embeddings: retrieval results feed
    # trajectory assertions and repeated-run reliability measurement, both of which need the
    # same query to return the same documents in the same order every time.
    def search(self, query: str, limit: int = 3) -> Sequence[KbDocument]:
        if not 1 <= limit <= MAX_SEARCH_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_SEARCH_LIMIT}")
        # The query will reach here from model output once agents exist, so it is bounded
        # at the point it enters rather than trusted to be reasonable.
        if len(query) > MAX_QUERY_LENGTH:
            raise ValueError(f"query must be at most {MAX_QUERY_LENGTH} characters")

        query_tokens = _tokenize(query)
        if not query_tokens:
            return ()

        scored: list[tuple[int, str, KbDocument]] = []
        for document in self._documents:
            title_hits = len(query_tokens & _tokenize(document.title))
            body_hits = len(query_tokens & _tokenize(document.body))
            score = title_hits * 2 + body_hits
            if score > 0:
                scored.append((-score, document.document_id, document))

        scored.sort(key=lambda entry: (entry[0], entry[1]))
        return tuple(document for _, _, document in scored[:limit])
