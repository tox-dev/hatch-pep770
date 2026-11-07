from __future__ import annotations


class SbomError(Exception):
    """Base of the errors this package raises; the command line reports them without a traceback."""


class SettingsError(SbomError, TypeError):
    """A setting has the wrong type."""


class WheelError(SbomError, ValueError):
    """A wheel, built or bundled, lacks what its SBOM needs to describe it."""


class SourceRevisionError(SbomError):
    """The project is a git checkout, but git cannot read its revision."""


class MissingExtraError(SbomError, ImportError):
    """A feature needs an optional extra that is not installed."""


__all__ = [
    "MissingExtraError",
    "SbomError",
    "SettingsError",
    "SourceRevisionError",
    "WheelError",
]
