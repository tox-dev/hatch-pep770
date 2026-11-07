"""
Build every input the benchmarks read, once, into a work directory.

This is the only step that needs the network: the fat build environment and virtualenv's zipapp download wheels. The
timed runs then read only what this wrote, listed in ``fixtures.json``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path
from typing import Final

#: a fixed build time, so every SBOM the fixtures and the timed runs write is the same
SOURCE_DATE_EPOCH: Final[str] = "1767225600"
#: resolve the fat environment as of this day, so every machine installs the same distributions
_EXCLUDE_NEWER: Final[str] = "2026-10-01T00:00:00Z"
# packages whose dependency closure gives a build environment of about seventy distributions, pure and platform ones,
# among them botocore, whose RECORD lists thousands of files
_FAT_PACKAGES: Final[tuple[str, ...]] = (
    "black",
    "boto3",
    "click",
    "cryptography",
    "httpx",
    "hypothesis",
    "jinja2",
    "pydantic",
    "pytest",
    "pyyaml",
    "requests",
    "rich",
    "setuptools",
    "sphinx",
    "tox",
    "wheel",
)
#: component counts of the hostile documents: the default cap, which still gets the full schema check, and twice it
_HOSTILE_COMPONENTS: Final[tuple[int, ...]] = (5_000, 10_000)
_LICENSE: Final[str] = (
    "MIT License\n\nCopyright (c) 2026 Bench Authors\n\nPermission is hereby granted, free of charge.\n"
)


def prepare(work: Path, project: Path, virtualenv: Path | None) -> None:
    work.mkdir(parents=True, exist_ok=True)
    os.environ["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    fixtures: Final[dict[str, str]] = {}
    fixtures["small"] = str(_small_project(work / "small"))
    fixtures["small-wheel"] = str(_hatchling_wheel(work / "small", work / "small-dist"))
    for count in _HOSTILE_COMPONENTS:
        target = work / f"hostile-{count // 1000}k.cdx.json"
        fixtures[f"hostile-{count // 1000}k"] = str(_hostile_document(Path(fixtures["small-wheel"]), target, count))
    fixtures["meson"] = str(_meson_project(work / "meson"))
    fixtures["meson-wheel"] = str(_meson_wheel(work / "meson-dist"))
    fixtures["fat-env"] = _fat_environment(work / "fat-env")
    _snapshot(project, work / "python-sbom")
    fixtures["own-wheel"] = str(_hatchling_wheel(work / "python-sbom", work / "own-dist"))
    if virtualenv is not None:
        fixtures.update(_virtualenv(virtualenv, work))
    (work / "fixtures.json").write_text(f"{json.dumps(fixtures, indent=2)}\n", encoding="utf-8")
    sys.stdout.write(f"wrote {work / 'fixtures.json'}\n")


def _small_project(root: Path) -> Path:
    # a pure-Python project of forty modules that turns the hook on, as a typical hatchling user does
    shutil.rmtree(root, ignore_errors=True)
    (package := root / "src" / "proj").mkdir(parents=True)
    (root / "LICENSE").write_text(_LICENSE, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """\
[build-system]
build-backend = "hatchling.build"
requires = [ "hatchling", "python-sbom[hatch]" ]

[project]
name = "proj"
version = "1.0"
license = "MIT"
license-files = [ "LICENSE" ]
requires-python = ">=3.11"
dependencies = [ "packaging>=24" ]

[tool.hatch.build.targets.wheel]
packages = [ "src/proj" ]

[tool.hatch.build.targets.wheel.hooks.python-sbom]

[tool.python-sbom]
supplier = { name = "Bench Authors", url = [ "https://example.org" ] }
repository = "https://github.com/example/proj"
""",
        encoding="utf-8",
    )
    (package / "__init__.py").write_text('"""A small project."""\n', encoding="utf-8")
    for index in range(40):
        (package / f"module_{index:02d}.py").write_text(
            "".join(f"def function_{name}() -> int:\n    return {name}\n\n\n" for name in range(50)), encoding="utf-8"
        )
    _commit(root)
    return root


def _commit(root: Path) -> None:
    # a checkout, as projects build from one, so the timed runs include reading the source revision with git
    _run(["git", "init", "--quiet", str(root)])
    _run(["git", "-C", str(root), "add", "."])
    _run([
        "git",
        "-C",
        str(root),
        "-c",
        "user.name=bench",
        "-c",
        "user.email=bench@example.org",
        "commit",
        "--quiet",
        "--no-verify",
        "--no-gpg-sign",
        "-m",
        "bench fixture",
    ])


def _run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, cwd=cwd, env=env)


def _hatchling_wheel(root: Path, directory: Path) -> Path:
    # without isolation, in this environment, so the hook under test is the one installed here
    shutil.rmtree(directory, ignore_errors=True)
    _run([sys.executable, "-m", "hatchling", "build", "--target", "wheel", "--directory", str(directory)], cwd=root)
    (wheel,) = directory.glob("*.whl")
    return wheel


def _hostile_document(wheel: Path, target: Path, count: int) -> Path:
    # the small project's SBOM with every component in one array of unique ones: over the default component cap the
    # document is rejected before the schema check, at or under it the uniqueItems check compares every pair of them.
    # The build tools go, as their file components would count toward the cap too
    with zipfile.ZipFile(wheel) as archive:
        (name,) = (member for member in archive.namelist() if "/sboms/" in member)
        hostile = json.loads(archive.read(name))
    hostile["metadata"]["tools"]["components"] = []
    hostile["components"] = [{"type": "library", "bom-ref": f"r{index}", "name": f"n{index}"} for index in range(count)]
    target.write_text(json.dumps(hostile), encoding="utf-8")
    return target


def _meson_project(root: Path) -> Path:
    # the project directory `python-sbom embed` reads [tool.python-sbom] and the source revision from
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    (root / "LICENSE").write_text(_LICENSE, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        """\
[build-system]
build-backend = "mesonpy"
requires = [ "meson-python" ]

[project]
name = "meson-proj"
version = "1.0"
license = "MIT"
license-files = [ "LICENSE" ]

[tool.python-sbom]
supplier = { name = "Bench Authors", url = [ "https://example.org" ] }
""",
        encoding="utf-8",
    )
    _commit(root)
    return root


def _meson_wheel(directory: Path) -> Path:
    # what meson-python writes: a platform wheel holding an extension module next to its Python sources
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    abi = f"cp{sys.version_info.major}{sys.version_info.minor}"
    platform = sysconfig.get_platform().replace("-", "_").replace(".", "_")
    dist_info = "meson_proj-1.0.dist-info"
    generator = random.Random(0)  # ruff: ignore[suspicious-non-cryptographic-random-usage] # only needs the same bytes on every run
    members: Final[dict[str, bytes]] = {
        "meson_proj/__init__.py": b'"""A meson-python project."""\n',
        f"meson_proj/_core{sysconfig.get_config_var('EXT_SUFFIX')}": generator.randbytes(4 * 1024 * 1024),
        **{
            f"meson_proj/module_{index:02d}.py": "".join(
                f"def function_{name}() -> int:\n    return {name}\n\n\n" for name in range(50)
            ).encode("utf-8")
            for index in range(30)
        },
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.4\nName: meson-proj\nVersion: 1.0\nLicense-Expression: MIT\nLicense-File: LICENSE\n"
            b"Requires-Python: >=3.11\nRequires-Dist: requests>=2\n"
        ),
        f"{dist_info}/WHEEL": (
            f"Wheel-Version: 1.0\nGenerator: meson\nRoot-Is-Purelib: false\nTag: {abi}-{abi}-{platform}\n"
        ).encode(),
        f"{dist_info}/licenses/LICENSE": _LICENSE.encode(),
    }
    record = "".join(
        f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()},{len(data)}\n"
        for name, data in members.items()
    )
    wheel = directory / f"meson_proj-1.0-{abi}-{abi}-{platform}.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as handle:
        for name, data in {**members, f"{dist_info}/RECORD": f"{record}{dist_info}/RECORD,,\n".encode()}.items():
            handle.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    return wheel


def _fat_environment(target: Path) -> str:
    if (uv := shutil.which("uv")) is None:
        msg = "the fat build environment needs uv on PATH"
        raise SystemExit(msg)
    shutil.rmtree(target, ignore_errors=True)
    _run([uv, "venv", "--quiet", "--python", sys.executable, str(target)])
    python = target / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    _run([
        uv,
        "pip",
        "install",
        "--quiet",
        "--python",
        str(python),
        "--exclude-newer",
        _EXCLUDE_NEWER,
        *_FAT_PACKAGES,
    ])
    return _output([str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"]).strip()


def _output(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def _snapshot(source: Path, target: Path) -> Path:
    # a clone of the checkout plus its uncommitted changes, so builds write their version files there and never into the
    # checkout itself; --shared borrows its objects, so even a detached HEAD resolves
    shutil.rmtree(target, ignore_errors=True)
    _run(["git", "clone", "--quiet", "--shared", "--no-checkout", str(source), str(target)])
    head = _output(["git", "-C", str(source), "rev-parse", "HEAD"]).strip()
    _run(["git", "-C", str(target), "checkout", "--quiet", "--detach", head])
    if diff := subprocess.run(
        ["git", "-C", str(source), "diff", "--binary", "HEAD"], check=True, capture_output=True
    ).stdout:
        subprocess.run(["git", "-C", str(target), "apply", "--index"], check=True, input=diff)
    for name in _output(["git", "-C", str(source), "ls-files", "--others", "--exclude-standard", "-z"]).split("\0"):
        if name:
            (target / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, target / name)
    return target


def _virtualenv(source: Path, work: Path) -> dict[str, str]:
    root = _snapshot(source, work / "virtualenv")
    wheel = _hatchling_wheel(root, work / "virtualenv-dist")
    zipapp = work / "virtualenv.pyz"
    _run(
        [sys.executable, "-m", "tasks.make_zipapp", "--wheel-dir", str(wheel.parent), "--dest", str(zipapp)],
        cwd=root,
        env={**os.environ, "PYTHONPATH": str(root)},
    )
    embedded = work / "virtualenv-sbom.pyz"
    shutil.copyfile(zipapp, embedded)
    sbom = work / "virtualenv.pyz.cdx.json"
    _run([
        sys.executable,
        "-m",
        "python_sbom",
        "archive",
        str(embedded),
        "--root",
        str(root),
        "--build-script",
        "tasks/make_zipapp.py",
        "--output",
        str(sbom),
        "--embed",
    ])
    embed = root / "src" / "virtualenv" / "seed" / "wheels" / "embed"
    return {
        "virtualenv": str(root),
        "virtualenv-wheel": str(wheel),
        "zipapp": str(zipapp),
        "zipapp-embedded": str(embedded),
        "zipapp-sbom": str(sbom),
        # the newest of each, the wheels virtualenv seeds on current Pythons
        "pip-wheel": str(max(embed.glob("pip-*.whl"), key=_wheel_version)),
        "setuptools-wheel": str(max(embed.glob("setuptools-*.whl"), key=_wheel_version)),
    }


def _wheel_version(wheel: Path) -> tuple[int, ...]:
    return tuple(int(part) for part in wheel.name.split("-")[1].split(".") if part.isdigit())


def load(work: Path) -> dict[str, str]:
    if not (manifest := work / "fixtures.json").is_file():
        msg = f"{manifest} does not exist; run `python -m bench prepare` first"
        raise SystemExit(msg)
    return json.loads(manifest.read_text(encoding="utf-8"))


__all__ = [
    "SOURCE_DATE_EPOCH",
    "load",
    "prepare",
]
