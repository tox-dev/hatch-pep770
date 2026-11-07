from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from python_sbom._cli._main import main
from python_sbom._formats._json import dumps

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import Describe


def test_spdx(tmp_path: Path, describe: Describe) -> None:
    (source := tmp_path / "example.cdx.json").write_bytes(dumps(describe()))
    main(["spdx", str(source), str(target := tmp_path / "example.spdx.json")])
    assert json.loads(target.read_text(encoding="utf-8"))["spdxVersion"] == "SPDX-2.3"


def test_spdx_refuses_non_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (source := tmp_path / "other.json").write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == f"python-sbom: {source} is not a CycloneDX document python-sbom can render\n"


def test_spdx_refuses_malformed_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    document = {"metadata": {"component": {"bom-ref": "app", "name": "app"}}, "components": [{"name": "x"}]}
    (source := tmp_path / "broken.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err.startswith(
        f"python-sbom: {source} is not a CycloneDX document python-sbom can render: "
    )
