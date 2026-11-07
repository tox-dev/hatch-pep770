from __future__ import annotations

import hashlib
import platform
import sys
import time
from typing import TYPE_CHECKING

import pytest

from python_sbom import (
    Interpreter,
    RecordRow,
    Revision,
    SettingsError,
    SourceRevisionError,
    collect_facts,
    default_revision,
    git_revision,
)

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Git, Install

    from python_sbom import BuildFacts


def test_epoch_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    facts = collect_facts(tmp_path, no_revision, [], 0)
    assert facts.epoch == 1_700_000_000
    assert facts.epoch_from_environment


def no_revision(_root: Path, /) -> None:
    return None


def test_epoch_default(tmp_path: Path) -> None:
    facts = collect_facts(tmp_path, no_revision, [], 42)
    assert (facts.epoch, facts.epoch_from_environment) == (42, False)


def test_empty_epoch_is_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "")
    facts = collect_facts(tmp_path, no_revision, [], 42)
    assert (facts.epoch, facts.epoch_from_environment) == (42, False)


def test_epoch_without_default_is_now(tmp_path: Path) -> None:
    before = int(time.time())
    assert before <= collect_facts(tmp_path, no_revision, [], None).epoch <= time.time()


def test_invalid_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    with pytest.raises(SettingsError, match="SOURCE_DATE_EPOCH must be a Unix timestamp, got 'yesterday'"):
        collect_facts(tmp_path, no_revision, [], None)


def test_interpreter(tmp_path: Path) -> None:
    assert collect_facts(tmp_path, no_revision, [], 0).interpreter == Interpreter(
        name=sys.implementation.name,
        version=platform.python_version(),
        implementation=platform.python_implementation(),
    )


def test_revision_reads_root(tmp_path: Path) -> None:
    def reader(root: Path, /) -> Revision:
        return Revision(commit=root.name, dirty=False)

    assert collect_facts(tmp_path, reader, [], 0).revision == Revision(commit=tmp_path.name, dirty=False)


def test_default_path_is_this_interpreter(tmp_path: Path) -> None:
    names = {
        distribution.metadata["Name"] for distribution in collect_facts(tmp_path, no_revision, None, 0).distributions
    }
    assert "pytest" in names


def test_pure_distribution_files(tmp_path: Path, install: Install) -> None:
    # nested, so the console script, two levels up as installers write it, stays inside the test's directory
    install(
        site := tmp_path / "lib" / "site-packages",
        "Name: alpha\nVersion: 1.0\n",
        {
            "alpha/__init__.py": b"x = 1\n",
            "../../bin/alpha": b"#!/usr/bin/python\n",
            "alpha-1.0.dist-info/INSTALLER": b"uv\n",
            "alpha-1.0.dist-info/REQUESTED": b"",
            "alpha-1.0.dist-info/direct_url.json": b'{"url": "file:///tmp/alpha.whl", "archive_info": {}}',
            "alpha-1.0.dist-info/uv_cache.json": b'{"timestamp": 1}',
        },
    )
    (distribution,) = facts_from(site).distributions
    assert distribution.files == [
        RecordRow(
            path="alpha/__init__.py", algorithm="SHA-256", digest=hashlib.sha256(b"x = 1\n").hexdigest(), size="6"
        ),
        RecordRow(
            path="alpha-1.0.dist-info/METADATA",
            algorithm="SHA-256",
            digest=hashlib.sha256(b"Name: alpha\nVersion: 1.0\n").hexdigest(),
            size="25",
        ),
        RecordRow(
            path="alpha-1.0.dist-info/WHEEL",
            algorithm="SHA-256",
            digest=hashlib.sha256(b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n").hexdigest(),
            size="41",
        ),
    ]


def facts_from(site: Path) -> BuildFacts:
    return collect_facts(site, no_revision, [str(site)], 0)


def test_platform_distribution_lists_no_files(tmp_path: Path, install: Install) -> None:
    install(tmp_path, "Name: native\nVersion: 1.0\n", {"native.so": b"\x7fELF"}, purelib=False)
    assert facts_from(tmp_path).distributions[0].files == []


def test_editable_distribution_lists_no_files(tmp_path: Path, install: Install) -> None:
    editable = '{"url": "file:///checkout", "dir_info": {"editable": true}}'
    install(tmp_path, "Name: local\nVersion: 1.0\n", {"local.pth": b"/checkout/src\n"}, direct_url=editable)
    assert facts_from(tmp_path).distributions[0].files == []


def test_first_distribution_on_path_wins(tmp_path: Path, install: Install) -> None:
    install(first := tmp_path / "first", "Name: alpha\nVersion: 1.0\n", {})
    install(second := tmp_path / "second", "Name: Alpha\nVersion: 2.0\n", {})
    (distribution,) = collect_facts(tmp_path, no_revision, [str(first), str(second)], 0).distributions
    assert distribution.metadata["Version"] == "1.0"


def test_depends_on_installed_requirements_that_apply(tmp_path: Path, install: Install) -> None:
    install(
        tmp_path,
        "Name: alpha\nVersion: 1.0\nRequires-Dist: Beta>=1\nRequires-Dist: gamma; python_version < '3'\n"
        "Requires-Dist: delta; extra == 'cli'\nRequires-Dist: missing\n",
        {},
    )
    for name in ("beta", "gamma", "delta"):
        install(tmp_path, f"Name: {name}\nVersion: 1.0\n", {})
    by_name = {distribution.metadata["Name"]: distribution for distribution in facts_from(tmp_path).distributions}
    assert by_name["alpha"].depends_on == ["beta"]


def test_commit_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", "c0ffee")
    assert default_revision(tmp_path) == Revision(commit="c0ffee", dirty=False)


@pytest.fixture
def checkout(tmp_path: Path, git: Git) -> Path:
    (tmp_path / "checkout" / "tracked.txt").write_text("one\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("commit", "--quiet", "--message", "first")
    return tmp_path / "checkout"


def test_git_revision(checkout: Path, git: Git) -> None:
    assert default_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_git_revision_dirty(checkout: Path, git: Git) -> None:
    (checkout / "tracked.txt").write_text("two\n", encoding="utf-8")
    assert git_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=True)


def test_untracked_files_leave_revision_clean(checkout: Path) -> None:
    (checkout / "untracked.txt").write_text("new\n", encoding="utf-8")
    revision = git_revision(checkout)
    assert revision is not None
    assert not revision.dirty


def test_git_revision_from_subdirectory(checkout: Path, git: Git) -> None:
    (subdirectory := checkout / "packages" / "one").mkdir(parents=True)
    assert git_revision(subdirectory) == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_git_revision_before_first_commit(tmp_path: Path, git: Git) -> None:
    git("status")
    assert git_revision(tmp_path / "checkout") is None


def test_git_revision_outside_checkout(tmp_path: Path) -> None:
    assert git_revision(tmp_path) is None


def test_git_revision_without_git(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    assert git_revision(checkout) is None


def test_git_revision_unreadable_checkout(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text(f"gitdir: {tmp_path / 'missing'}\n", encoding="utf-8")
    with pytest.raises(SourceRevisionError, match="git rev-parse HEAD failed in"):
        git_revision(tmp_path)


@pytest.mark.parametrize(
    ("archival", "expected"),
    [
        pytest.param(f"node: {'a' * 40}\n", Revision(commit="a" * 40, dirty=False), id="expanded"),
        pytest.param("node: $Format:%H$\n", None, id="unexpanded"),
    ],
)
def test_git_archival(tmp_path: Path, archival: str, expected: Revision | None) -> None:
    (tmp_path / ".git_archival.txt").write_text(archival, encoding="utf-8")
    assert default_revision(tmp_path) == expected


def test_no_revision_source(tmp_path: Path) -> None:
    assert default_revision(tmp_path) is None
