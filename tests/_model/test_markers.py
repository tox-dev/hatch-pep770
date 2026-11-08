from __future__ import annotations

import subprocess
import sys

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
        # only the conditions on extra decide, so a marker no environment satisfies still leaves the requirement listed
        pytest.param('click; python_version < "3" and python_version >= "3"', True, id="environment-contradiction"),
        pytest.param('click; (os_name == "nt" and os_name != "nt") or extra == "a"', True, id="contradiction-or-extra"),
        pytest.param('click; extra in "a,b"', True, id="extra-in"),
        pytest.param('click; extra not in "a,b"', False, id="extra-not-in"),
        # extra compared as a version has no answer, so it stays unknown
        pytest.param('click; extra ~= "1.0" and os_name == "nt"', True, id="extra-compatible-release"),
    ],
)
def test_applies_without_extras(requirement: str, applies: bool) -> None:
    assert applies_without_extras(Requirement(requirement)) is applies


def test_verdicts_hold_under_python_optimize() -> None:
    # python -O strips assert statements, through which dep-logic turned these comparisons on extra away and so lost
    # requirements that apply; the verdicts here must not depend on the mode
    markers = {
        'extra in "a,b" and os_name == "nt"': True,
        'extra not in "a,b" or python_version < "3.11"': True,
        'extra < "b" and sys_platform == "linux"': False,
        '"a" in extra or os_name == "nt"': True,
        'extra not in "" and python_version >= "3"': False,
        '(extra >= "a" or extra == "cli") and os_name != "nt"': False,
    }
    script = (
        "import sys\n"
        "from packaging.requirements import Requirement\n"
        "from python_sbom._model._markers import applies_without_extras\n"
        "print(*(applies_without_extras(Requirement(f'click; {marker}')) for marker in sys.argv[1:]))\n"
    )
    result = subprocess.run([sys.executable, "-O", "-c", script, *markers], capture_output=True, text=True, check=True)
    assert result.stdout.split() == [str(verdict) for verdict in markers.values()]


def test_requirement_kept_without_packaging_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    # None in sys.modules makes the import fail, as when a packaging release moves its private marker tree
    monkeypatch.setitem(sys.modules, "packaging._parser", None)
    assert applies_without_extras(Requirement('click; extra == "cli"')) is True


def test_requirement_kept_without_marker_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    # a packaging release that renames the private attribute holding the parsed tree
    requirement = Requirement('click; extra == "cli"')
    monkeypatch.delattr(requirement.marker, "_markers")
    assert applies_without_extras(requirement) is True
