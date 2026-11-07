from __future__ import annotations

from typing import TYPE_CHECKING

from python_sbom import _core

if TYPE_CHECKING:
    import uuid

    from ._types import Body, Document, Property


def with_header(body: Body, namespace: uuid.UUID) -> Document:
    # a provider contributes refs of its own, so the document is checked before it is written rather than by validate
    return _core.with_header(body, str(namespace))


def contributed_properties(properties: list[Property], prefix: str) -> list[Property]:
    return _core.contributed_properties(properties, prefix)


__all__ = [
    "contributed_properties",
    "with_header",
]
