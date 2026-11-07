from __future__ import annotations


class SbomError(Exception):
    """Base of the errors this package raises; the command line reports them without a traceback."""


# callers catch these as SbomError, or as the built-in some of them also are; SettingsError covers every option,
# file or variable the project sets wrongly
class SettingsError(SbomError): ...  # simplint: ignore[SMP704] # see above


class WheelError(SbomError, ValueError): ...  # simplint: ignore[SMP704] # see above


# a Requires-Dist that does not parse, as packaging's InvalidRequirement reported it
class InvalidRequirement(ValueError): ...  # simplint: ignore[SMP704] # see above


__all__ = [
    "InvalidRequirement",
    "SbomError",
    "SettingsError",
    "WheelError",
]
