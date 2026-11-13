"""Print a greeting the C extension builds."""

from __future__ import annotations

from ._greet import hello


def main() -> None:  # simplint: ignore[undocumented-public-api]  # CLI entry point
    print(hello())
