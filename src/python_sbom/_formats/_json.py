"""Write documents as JSON, and parse JSON input and check it has the fields a document needs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, TypeAlias

from python_sbom._errors import SbomError

if TYPE_CHECKING:
    from typing import TypeIs  # new in 3.13; annotations here are never evaluated

    from python_sbom._model._types import Document

    from ._spdx import Spdx

# a JSON value, as json.loads hands it over
Json: TypeAlias = "str | int | float | bool | list[Json] | dict[str, Json] | None"


def dumps(document: Document | Spdx) -> bytes:
    return f"{json.dumps(document, indent=2)}\n".encode()


def load_json(raw: bytes) -> Any:  # ruff: ignore[any-type] # json.loads' own type: any shape until checked
    # why bytes are no JSON value, worded once for validate and for spdx, which renders a document without validating it
    try:
        return json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as error:
        msg = f"is not UTF-8: {error.reason} at byte {error.start}"
        raise SbomError(msg) from error
    except json.JSONDecodeError as error:
        msg = f"is not JSON: {error}"
        raise SbomError(msg) from error
    except RecursionError as error:
        # the JSON parser recurses once per level and gives up near the recursion limit, long before the depth check
        # sees the document
        msg = "nests too deep for the JSON parser to read"
        raise SbomError(msg) from error


def is_document(value: object) -> TypeIs[Document]:
    # what the SPDX rendering reads without a fallback; the schema leaves even these optional
    return isinstance(value, dict) and all(
        has_path(value, ("metadata", "component", key)) for key in ("bom-ref", "name")
    )


def has_path(value: Json, path: tuple[str, ...]) -> bool:
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return False
        value = value[key]
    return True


__all__ = [
    "Json",
    "dumps",
    "has_path",
    "is_document",
    "load_json",
]
