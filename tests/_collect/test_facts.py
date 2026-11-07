from __future__ import annotations

import hashlib
import platform
import re
import sys
import time
from typing import TYPE_CHECKING

import pytest

from python_sbom._collect._facts import REVISION_FILE, collect_facts, default_revision, git_revision
from python_sbom._errors import SettingsError
from python_sbom._model._inputs import Interpreter, RecordRow, Revision

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Git, Install

    from python_sbom._model._inputs import BuildFacts


def test_epoch_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    facts = collect_facts(tmp_path, no_revision, path=[], default_epoch=0)
    assert facts.epoch == 1_700_000_000
    assert facts.epoch_from_environment


def no_revision(_root: Path, /) -> None:
    return None


def test_epoch_default(tmp_path: Path) -> None:
    facts = collect_facts(tmp_path, no_revision, path=[], default_epoch=42)
    assert (facts.epoch, facts.epoch_from_environment) == (42, False)


def test_empty_epoch_is_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "")
    facts = collect_facts(tmp_path, no_revision, path=[], default_epoch=42)
    assert (facts.epoch, facts.epoch_from_environment) == (42, False)


def test_epoch_without_default_is_now(tmp_path: Path) -> None:
    before = int(time.time())
    assert before <= collect_facts(tmp_path, no_revision, path=[]).epoch <= time.time()


def test_invalid_epoch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    with pytest.raises(SettingsError, match="SOURCE_DATE_EPOCH must be a Unix timestamp, got 'yesterday'"):
        collect_facts(tmp_path, no_revision, path=[])


def test_interpreter(tmp_path: Path) -> None:
    assert collect_facts(tmp_path, no_revision, path=[], default_epoch=0).interpreter == Interpreter(
        name=sys.implementation.name,
        version=platform.python_version(),
        implementation=platform.python_implementation(),
    )


def test_revision_reads_root(tmp_path: Path) -> None:
    def reader(root: Path, /) -> Revision:
        return Revision(commit=root.name, dirty=False)

    assert collect_facts(tmp_path, reader, path=[], default_epoch=0).revision == Revision(
        commit=tmp_path.name, dirty=False
    )


def test_default_path_is_this_interpreter(tmp_path: Path) -> None:
    names = {
        distribution.metadata.name
        for distribution in collect_facts(tmp_path, no_revision, default_epoch=0).distributions
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
    return collect_facts(site, no_revision, path=[str(site)], default_epoch=0)


def test_platform_distribution_lists_no_files(tmp_path: Path, install: Install) -> None:
    install(tmp_path, "Name: native\nVersion: 1.0\n", {"native.so": b"\x7fELF"}, purelib=False)
    assert facts_from(tmp_path).distributions[0].files == []


def test_editable_distribution_lists_no_files(tmp_path: Path, install: Install) -> None:
    editable = '{"url": "file:///checkout", "dir_info": {"editable": true}}'
    install(tmp_path, "Name: local\nVersion: 1.0\n", {"local.pth": b"/checkout/src\n"}, direct_url=editable)
    assert facts_from(tmp_path).distributions[0].files == []


def test_directory_install_not_editable_lists_files(tmp_path: Path, install: Install) -> None:
    install(tmp_path, "Name: local\nVersion: 1.0\n", {}, direct_url='{"url": "file:///checkout", "dir_info": {}}')
    assert [row.path for row in facts_from(tmp_path).distributions[0].files] == [
        "local-1.0.dist-info/METADATA",
        "local-1.0.dist-info/WHEEL",
    ]


@pytest.mark.parametrize(
    ("direct_url", "message"),
    [
        pytest.param("{", "Expecting property name", id="not-json"),
        pytest.param('{"dir_info": {"editable": true}}', "Missing required value in 'url'", id="no-url"),
        pytest.param(
            '{"url": "file:///checkout", "dir_info": {"editable": "yes"}}',
            r"Unexpected type str \(expected bool\) in 'dir_info.editable'",
            id="editable-not-bool",
        ),
    ],
)
def test_malformed_direct_url_reads_as_not_editable(
    tmp_path: Path, install: Install, direct_url: str, message: str
) -> None:
    install(tmp_path, "Name: local\nVersion: 1.0\n", {}, direct_url=direct_url)
    with pytest.warns(UserWarning, match=f"read the direct_url.json of local as not editable: {message}"):
        files = facts_from(tmp_path).distributions[0].files
    assert len(files) == 2


def test_first_distribution_on_path_wins(tmp_path: Path, install: Install) -> None:
    install(first := tmp_path / "first", "Name: alpha\nVersion: 1.0\n", {})
    install(second := tmp_path / "second", "Name: Alpha\nVersion: 2.0\n", {})
    (distribution,) = collect_facts(
        tmp_path, no_revision, path=[str(first), str(second)], default_epoch=0
    ).distributions
    assert distribution.metadata.version == "1.0"


def test_depends_on_installed_requirements_that_apply(tmp_path: Path, install: Install) -> None:
    install(
        tmp_path,
        "Name: alpha\nVersion: 1.0\nRequires-Dist: Beta>=1\nRequires-Dist: gamma; python_version < '3'\n"
        "Requires-Dist: delta; extra == 'cli'\nRequires-Dist: missing\n",
        {},
    )
    for name in ("beta", "gamma", "delta"):
        install(tmp_path, f"Name: {name}\nVersion: 1.0\n", {})
    by_name = {distribution.metadata.name: distribution for distribution in facts_from(tmp_path).distributions}
    assert by_name["alpha"].depends_on == ["beta"]


def test_egg_info_distribution(tmp_path: Path) -> None:
    (egg_info := tmp_path / "legacy-1.0-py3.14.egg-info").mkdir()
    (egg_info / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: Legacy\nVersion: 1.0\n", encoding="utf-8")
    (distribution,) = facts_from(tmp_path).distributions
    assert (distribution.name, distribution.metadata.version, distribution.files) == ("legacy", "1.0", [])


def test_recorded_file_missing_on_disk_is_listed(tmp_path: Path, install: Install) -> None:
    # the install recorded it, and Python 3.11 lists such a file too, where later versions' Distribution.files drop it
    install(tmp_path, "Name: alpha\nVersion: 1.0\n", {"alpha.py": b"x = 1\n"})
    (tmp_path / "alpha.py").unlink()
    assert [row.path for row in facts_from(tmp_path).distributions[0].files] == [
        "alpha.py",
        "alpha-1.0.dist-info/METADATA",
        "alpha-1.0.dist-info/WHEEL",
    ]


@pytest.mark.parametrize(
    ("row", "issue"),
    [
        pytest.param("alpha.py,sha256=x", "expected 3 elements, got 2", id="two-columns"),
        pytest.param("alpha.py,sha256=x,big", "`size` cannot be non-integer", id="size-not-integer"),
        pytest.param("alpha.py,nohash,1", "`hash` does not follow the required format", id="hash-without-name"),
    ],
)
def test_malformed_record_lists_no_files(tmp_path: Path, install: Install, row: str, issue: str) -> None:
    install(tmp_path, "Name: alpha\nVersion: 1.0\n", {})
    (tmp_path / "alpha-1.0.dist-info" / "RECORD").write_bytes(f"{row}\n".encode())
    with pytest.warns(UserWarning, match=f"listed no files of alpha, its RECORD is malformed: .*{re.escape(issue)}"):
        assert facts_from(tmp_path).distributions[0].files == []


@pytest.mark.parametrize(
    "files",
    [
        pytest.param({}, id="without-metadata"),
        pytest.param({"METADATA": "Name: broken\n"}, id="without-version"),
    ],
)
def test_distribution_without_name_and_version_left_out(
    tmp_path: Path, install: Install, files: dict[str, str]
) -> None:
    install(tmp_path, "Name: ok\nVersion: 1.0\n", {})
    (broken := tmp_path / "broken-1.0.dist-info").mkdir()
    for name, text in files.items():
        (broken / name).write_text(text, encoding="utf-8")
    assert [distribution.name for distribution in facts_from(tmp_path).distributions] == ["ok"]


def test_invalid_requirement_left_out(tmp_path: Path, install: Install) -> None:
    install(tmp_path, "Name: old\nVersion: 1.0\nRequires-Dist: pytz (>dev)\nRequires-Dist: pytz\n", {})
    install(tmp_path, "Name: pytz\nVersion: 1.0\n", {})
    with pytest.warns(UserWarning, match=r"left out the requirement 'pytz \(>dev\)' of old: "):
        by_name = {distribution.name: distribution for distribution in facts_from(tmp_path).distributions}
    assert by_name["old"].depends_on == ["pytz"]


@pytest.mark.parametrize("commit", [pytest.param("a" * 40, id="sha1"), pytest.param("b" * 64, id="sha256")])
def test_commit_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commit: str) -> None:
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", commit)
    assert default_revision(tmp_path) == Revision(commit=commit, dirty=False)


@pytest.mark.parametrize(
    "commit",
    [
        pytest.param("c0ffee", id="abbreviated"),
        pytest.param("A" * 40, id="uppercase"),
        pytest.param("a" * 41, id="between-lengths"),
        pytest.param(f"{'a' * 40}/../../evil", id="path"),
    ],
)
def test_commit_from_environment_must_be_full_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, commit: str
) -> None:
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", commit)
    with pytest.raises(SettingsError, match="PYTHON_SBOM_COMMIT must be a full lowercase hex commit hash"):
        default_revision(tmp_path)


def test_commit_from_environment_wins_over_git(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHON_SBOM_COMMIT", "a" * 40)
    assert default_revision(checkout) == Revision(commit="a" * 40, dirty=False)


@pytest.fixture
def checkout(tmp_path: Path, git: Git) -> Path:
    (root := tmp_path / "checkout").joinpath("pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (root / ".gitignore").write_text("build/\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return root


def test_revision_file(tmp_path: Path) -> None:
    (tmp_path / REVISION_FILE).write_text(f"node: {'d' * 40}\n", encoding="utf-8")
    assert default_revision(tmp_path) == Revision(commit="d" * 40, dirty=False)


def test_invalid_revision_file(tmp_path: Path) -> None:
    (tmp_path / REVISION_FILE).write_text("node: d\n", encoding="utf-8")
    with pytest.raises(SettingsError, match=r"\.python-sbom-revision must be a full lowercase hex commit hash"):
        default_revision(tmp_path)


def test_git_revision(checkout: Path, git: Git) -> None:
    assert default_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_git_revision_dirty(checkout: Path, git: Git) -> None:
    (checkout / "pyproject.toml").write_text("[project]\nname = 'changed'\n", encoding="utf-8")
    assert git_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=True)


def test_untracked_file_marks_revision_dirty(checkout: Path) -> None:
    # the build packages it, so the commit alone no longer describes the source
    (checkout / "backdoor.py").write_text("import os\n", encoding="utf-8")
    assert (revision := git_revision(checkout)) is not None
    assert revision.dirty


def test_ignored_file_leaves_revision_clean(checkout: Path) -> None:
    (checkout / "build").mkdir()
    (checkout / "build" / "output.txt").write_text("new\n", encoding="utf-8")
    assert (revision := git_revision(checkout)) is not None
    assert not revision.dirty


@pytest.fixture
def monorepo(tmp_path: Path, git: Git) -> Path:
    for project in ("one", "two"):
        (root := tmp_path / "checkout" / project).mkdir()
        (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "--message", "first")
    return tmp_path / "checkout"


def test_git_revision_of_project_in_subdirectory(monorepo: Path, git: Git) -> None:
    assert git_revision(monorepo / "one") == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_sibling_changes_leave_revision_clean(monorepo: Path) -> None:
    (monorepo / "two" / "pyproject.toml").write_text("[project]\nname = 'changed'\n", encoding="utf-8")
    (monorepo / "two" / "new.py").write_text("", encoding="utf-8")
    assert (revision := git_revision(monorepo / "one")) is not None
    assert not revision.dirty


def test_project_untracked_by_enclosing_checkout_uses_archival(checkout: Path) -> None:
    # an sdist unpacked under another project's build directory is not that project's commit
    (project := checkout / "build" / "project").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (project / ".git_archival.txt").write_text(f"node: {'e' * 40}\n", encoding="utf-8")
    assert default_revision(project) == Revision(commit="e" * 40, dirty=False)


@pytest.mark.parametrize(
    "project",
    [pytest.param(".", id="own-checkout"), pytest.param("build/project", id="enclosing-checkout")],
)
def test_git_runs_no_fsmonitor_command(tmp_path: Path, checkout: Path, git: Git, project: str) -> None:
    git("config", "core.fsmonitor", f"touch {(marker := tmp_path / 'ran').as_posix()}; false")
    (root := checkout / project).mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").touch()
    git_revision(root)
    assert not marker.exists()


def test_git_revision_before_first_commit(tmp_path: Path, git: Git) -> None:
    (tmp_path / "checkout" / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    git("add", "pyproject.toml")
    assert git_revision(tmp_path / "checkout") is None


def test_git_revision_outside_checkout(tmp_path: Path) -> None:
    assert git_revision(tmp_path) is None


def test_git_revision_without_git(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    assert git_revision(checkout) is None


@pytest.mark.parametrize(
    "git_file",
    [
        # a worktree copied without the main checkout, as into a container
        pytest.param("gitdir: {root}/missing\n", id="missing-gitdir"),
        # the marker uv leaves in an unpacked sdist it builds from
        pytest.param("", id="empty"),
    ],
)
def test_git_failure_warns_and_falls_back(tmp_path: Path, git_file: str) -> None:
    (tmp_path / ".git").write_text(git_file.format(root=tmp_path.as_posix()), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp_path / ".git_archival.txt").write_text(f"node: {'f' * 40}\n", encoding="utf-8")
    with pytest.warns(UserWarning, match="git cannot read the source revision in .*: fatal: "):
        assert default_revision(tmp_path) == Revision(commit="f" * 40, dirty=False)


def test_git_status_failure_leaves_revision_unknown(checkout: Path, git: Git) -> None:
    # a tree object lost from the store, so git knows HEAD but cannot compare the checkout with it
    tree = git("rev-parse", "HEAD^{tree}")
    (stored := checkout / ".git" / "objects" / tree[:2] / tree[2:]).chmod(0o644)
    stored.unlink()
    with pytest.warns(UserWarning, match="git cannot read the source revision in .*: error: bad tree object HEAD"):
        assert git_revision(checkout) is None


@pytest.mark.parametrize(
    ("archival", "expected"),
    [
        pytest.param(f"node: {'a' * 40}\n", Revision(commit="a" * 40, dirty=False), id="expanded"),
        pytest.param("node: $Format:%H$\n", None, id="unexpanded"),
        pytest.param(f"node: {'a' * 41}\n", None, id="not-a-commit"),
    ],
)
def test_git_archival(tmp_path: Path, archival: str, expected: Revision | None) -> None:
    (tmp_path / ".git_archival.txt").write_text(archival, encoding="utf-8")
    assert default_revision(tmp_path) == expected


def test_no_revision_source(tmp_path: Path) -> None:
    assert default_revision(tmp_path) is None
