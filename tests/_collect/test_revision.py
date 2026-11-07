from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from python_sbom._collect._revision import REVISION_FILE, default_revision, revision_reader
from python_sbom._errors import SbomError
from python_sbom._model._inputs import Revision

if TYPE_CHECKING:
    from pathlib import Path

    from conftest import Git


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
    with pytest.raises(SbomError, match="PYTHON_SBOM_COMMIT must be a full lowercase hex commit hash"):
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
    with pytest.raises(SbomError, match=r"\.python-sbom-revision must be a full lowercase hex commit hash"):
        default_revision(tmp_path)


def test_git_revision(checkout: Path, git: Git) -> None:
    assert default_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_git_revision_dirty(checkout: Path, git: Git) -> None:
    (checkout / "pyproject.toml").write_text("[project]\nname = 'changed'\n", encoding="utf-8")
    assert default_revision(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=True)


def test_untracked_file_marks_revision_dirty(checkout: Path) -> None:
    # the build packages it, so the commit alone no longer describes the source
    (checkout / "backdoor.py").write_text("import os\n", encoding="utf-8")
    assert (revision := default_revision(checkout)) is not None
    assert revision.dirty


def test_ignored_file_leaves_revision_clean(checkout: Path) -> None:
    (checkout / "build").mkdir()
    (checkout / "build" / "output.txt").write_text("new\n", encoding="utf-8")
    assert (revision := default_revision(checkout)) is not None
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
    assert default_revision(monorepo / "one") == Revision(commit=git("rev-parse", "HEAD"), dirty=False)


def test_sibling_changes_leave_revision_clean(monorepo: Path) -> None:
    (monorepo / "two" / "pyproject.toml").write_text("[project]\nname = 'changed'\n", encoding="utf-8")
    (monorepo / "two" / "new.py").write_text("", encoding="utf-8")
    assert (revision := default_revision(monorepo / "one")) is not None
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
    default_revision(root)
    assert not marker.exists()


def test_git_revision_before_first_commit(tmp_path: Path, git: Git) -> None:
    (tmp_path / "checkout" / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    git("add", "pyproject.toml")
    assert default_revision(tmp_path / "checkout") is None


def test_git_revision_outside_checkout(tmp_path: Path) -> None:
    assert default_revision(tmp_path) is None


def test_git_revision_without_git(checkout: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")
    assert default_revision(checkout) is None


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
        assert default_revision(checkout) is None


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


def test_given_commit_wins_over_checkout(checkout: Path) -> None:
    assert revision_reader("a" * 40)(checkout) == Revision(commit="a" * 40, dirty=False)


def test_given_commit_must_be_full_hash() -> None:
    with pytest.raises(SbomError, match="--commit must be a full lowercase hex commit hash"):
        revision_reader("c0ffee")


def test_no_given_commit_reads_checkout(checkout: Path, git: Git) -> None:
    assert revision_reader(None)(checkout) == Revision(commit=git("rev-parse", "HEAD"), dirty=False)
