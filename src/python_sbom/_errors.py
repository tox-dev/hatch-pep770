from __future__ import annotations


class SbomError(Exception):
    """Base of the errors this package raises; the command line reports them without a traceback."""


# validation reports every other error per document, and lets this one through, since it fails every document alike
class MissingExtraError(SbomError): ...  # simplint: ignore[SMP704] # see above


__all__ = [
    "MissingExtraError",
    "SbomError",
]
