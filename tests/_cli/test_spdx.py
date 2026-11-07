from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from python_sbom._cli._main import main
from python_sbom._formats._json import dumps
from python_sbom._validate._document import MAX_COMPONENTS, byte_limit

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


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        pytest.param(
            b"{", "is not JSON: Expecting property name enclosed in double quotes: line 1 column 2 (char 1)", id="json"
        ),
        pytest.param(b'{"name": "\xff"}', "is not UTF-8: invalid start byte at byte 10", id="utf-8"),
        pytest.param(b"[" * 100_000, "nests too deep for the JSON parser to read", id="nesting"),
    ],
)
def test_spdx_refuses_unreadable_source(
    content: bytes, problem: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (source := tmp_path / "source.json").write_bytes(content)
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == f"python-sbom: {source} {problem}\n"


def test_spdx_refuses_missing_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["spdx", str(source := tmp_path / "missing.json"), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == f"python-sbom: [Errno 2] No such file or directory: {str(source)!r}\n"


def test_spdx_refuses_oversized_source(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    limit = byte_limit(MAX_COMPONENTS)
    # sparse, so the test writes nothing; the size alone is refused, before any parsing
    with (source := tmp_path / "large.json").open("wb") as handle:
        handle.truncate(limit + 1)
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == (
        f"python-sbom: {source} is over {limit} bytes, the size limit of an SBOM python-sbom reads\n"
    )


def test_spdx_refuses_unparsable_timestamp(
    tmp_path: Path, describe: Describe, capsys: pytest.CaptureFixture[str]
) -> None:
    document = describe()
    document["metadata"]["timestamp"] = "yesterday"
    (source := tmp_path / "example.cdx.json").write_bytes(dumps(document))
    with pytest.raises(SystemExit):
        main(["spdx", str(source), str(tmp_path / "out.json")])
    assert capsys.readouterr().err == (
        f"python-sbom: {source} is not a CycloneDX document python-sbom can render:"
        " ValueError(\"Invalid isoformat string: 'yesterday'\")\n"
    )
