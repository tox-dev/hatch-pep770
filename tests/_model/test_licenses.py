from __future__ import annotations

from email import message_from_string
from typing import TYPE_CHECKING

import pytest

from python_sbom._model._licenses import licenses

if TYPE_CHECKING:
    from python_sbom import License


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        pytest.param(
            "mit or apache-2.0", [{"expression": "MIT OR Apache-2.0", "acknowledgement": "declared"}], id="canonical"
        ),
        pytest.param(
            "MIT WITH GPL-3.0-only",
            [{"license": {"name": "MIT WITH GPL-3.0-only", "acknowledgement": "declared"}}],
            id="invalid-kept-as-name",
        ),
    ],
)
def test_license_expression(expression: str, expected: list[License]) -> None:
    assert licenses(message_from_string(f"License-Expression: {expression}\n")) == expected
