from __future__ import annotations

import pytest
from packaging.requirements import Requirement

from python_sbom._model._markers import applies_without_extras


@pytest.mark.parametrize(
    ("requirement", "applies"),
    [
        pytest.param('click; extra == "cli"', False, id="extra"),
        pytest.param('click; "cli" == extra', False, id="extra-on-the-right"),
        pytest.param('click; extra != "cli"', True, id="not-extra"),
        pytest.param('click; python_version < "3.11"', True, id="environment"),
        pytest.param('click; extra == "cli" or python_version < "3.11"', True, id="extra-or-environment"),
        pytest.param('click; extra == "cli" and python_version < "3.11"', False, id="extra-and-environment"),
        pytest.param('click; (extra == "a" or extra == "b") and os_name == "nt"', False, id="grouped-extras"),
        pytest.param(
            'click; python_version < "3.11" and (extra == "a" or os_name == "nt")', True, id="grouped-unknown"
        ),
        pytest.param('click; python_version >= "3" or extra == "a"', True, id="environment-or-extra"),
        pytest.param("click", True, id="no-marker"),
        pytest.param('click; extra == "A_b" and extra != "a-b"', False, id="extra-names-normalized"),
        # no environment satisfies the marker, so no install ever pulls the requirement in
        pytest.param('click; python_version < "3" and python_version >= "3"', False, id="environment-contradiction"),
        pytest.param(
            'click; (os_name == "nt" and os_name != "nt") or extra == "a"', False, id="contradiction-or-extra"
        ),
        # dep-logic compares extra through == and != only, so other comparisons keep the requirement listed
        pytest.param('click; extra in "a,b"', True, id="extra-in"),
        pytest.param('click; extra not in "a,b"', True, id="extra-not-in"),
        pytest.param('click; extra ~= "1.0" and os_name == "nt"', True, id="extra-compatible-release"),
    ],
)
def test_applies_without_extras(requirement: str, applies: bool) -> None:
    assert applies_without_extras(Requirement(requirement)) is applies
