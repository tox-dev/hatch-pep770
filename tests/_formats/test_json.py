from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from python_sbom._formats._json import is_document

if TYPE_CHECKING:
    from python_sbom._formats._json import Json


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param({"metadata": {"component": {"bom-ref": "plain", "name": "plain"}}}, True, id="root-named"),
        pytest.param({"metadata": {"component": {"name": "plain"}}}, False, id="root-without-bom-ref"),
        pytest.param({"metadata": {"component": {"bom-ref": "plain"}}}, False, id="root-without-name"),
        pytest.param({"metadata": {}}, False, id="no-root"),
        pytest.param([], False, id="not-an-object"),
    ],
)
def test_is_document(value: Json, expected: bool) -> None:
    assert is_document(value) is expected
