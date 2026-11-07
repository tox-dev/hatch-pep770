# hatch-pep770

[![PyPI](https://img.shields.io/pypi/v/hatch-pep770?style=flat-square)](https://pypi.org/project/hatch-pep770/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/hatch-pep770.svg)](https://pypi.org/project/hatch-pep770/)
[![check](https://github.com/tox-dev/hatch-pep770/actions/workflows/check.yaml/badge.svg)](https://github.com/tox-dev/hatch-pep770/actions/workflows/check.yaml)

A [hatchling](https://hatch.pypa.io/latest/) build hook that writes a [CycloneDX](https://cyclonedx.org/) 1.6 SBOM into
every wheel at `<name>-<version>.dist-info/sboms/<name>.cdx.json`, where [PEP 770](https://peps.python.org/pep-0770/)
says installers and scanners look for it.

General-purpose SBOM scanners read installed environments or declared dependencies. They cannot see a wheel your project
bundles as a data file, and they say nothing about how a wheel was built. The SBOM this hook writes records:

- the project, from its core metadata: version, license, maintainers, project URLs, classifiers, and the source revision
  when the build runs in a git checkout;
- the runtime dependencies the wheel declares, unversioned, since the installer resolves them;
- every wheel the project bundles as a data file, with its SHA-256, license, files, and the packages it vendors;
- the build toolchain: the Python version, and every distribution in the build environment with its dependencies and,
  for pure-Python ones, the hash of each file.

It records nothing about the build machine and takes its timestamp from `SOURCE_DATE_EPOCH`, so rebuilding the same
source with the same toolchain and epoch reproduces the wheel byte for byte on any operating system or architecture.

## Use it

Add the hook to the build requirements and enable it:

```toml
[build-system]
build-backend = "hatchling.build"
requires = ["hatch-pep770>=0.1", "hatchling>=1.28"]

[tool.hatch.build.hooks.pep770]
```

hatchling 1.28 added SBOM support to wheels. With an older hatchling the hook prints a warning and the wheel carries no
SBOM, so a project that still builds on Python 3.9 (where hatchling stops at 1.27) can keep the hook enabled.

The hook only acts on the wheel target. Put it after any hook that sets the wheel tag, since the SBOM names the wheel
file in its attestation link.

## Options

All options are optional.

| Option           | Default                                                  | Meaning                                                                                                                                                    |
| ---------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `supplier`       | none                                                     | `{ name = "...", url = ["..."] }`, the organization that supplies the project; it becomes the SBOM's supplier and manufacturer and the project's supplier. |
| `repository`     | the first `Source`, `Repository` or `GitHub` project URL | Repository URL for the source revision, license and security policy links.                                                                                 |
| `default-branch` | `main`                                                   | Branch used in links to files in the repository.                                                                                                           |
| `bundled-wheels` | `[]`                                                     | Glob patterns, relative to the project root, of wheels the project ships as data files.                                                                    |

For example, a project that ships the wheels it installs into new environments:

```toml
[tool.hatch.build.hooks.pep770]
supplier = { name = "Python Packaging Authority", url = [
  "https://www.pypa.io",
] }
bundled-wheels = ["src/virtualenv/seed/wheels/embed/*.whl"]
```

A bundled wheel whose project URLs point to the same forge account as `repository` gets the same `supplier`. Its
vendored packages come from `_vendor/vendor.txt` (pip's manifest, whose entries must pin one exact version) and from any
`.dist-info/METADATA` under `_vendor/`.

Property names the hook writes start with the project name, for example `virtualenv:bundled-wheel`.

## Add project-specific detail

To say more about each bundled wheel, subclass the hook in a
[custom build hook](https://hatch.pypa.io/latest/plugins/build-hook/custom/) and override `bundled_wheel_properties`.
Its options then live under `[tool.hatch.build.hooks.custom]`, and the SBOM lists the script among the build tools:

```python
# hatch_build.py
from __future__ import annotations

from pathlib import Path

from hatch_pep770 import cyclonedx, plugin


class SbomBuildHook(plugin.Pep770BuildHook):
    def bundled_wheel_properties(self, wheel: Path) -> list[cyclonedx.Property]:
        return [{"name": "example:installed-for-python", "value": "3.14"}]


def get_build_hook() -> type[SbomBuildHook]:
    return SbomBuildHook
```

```toml
[tool.hatch.build.hooks.custom]
path = "hatch_build.py"
bundled-wheels = ["src/example/wheels/*.whl"]
```

The `get_build_hook` function tells hatchling which class to load, since the module also sees the base class.
`hatch_pep770.cyclonedx` holds the pieces the hook is built from (`build_tools`, `component_from_metadata`, `document`)
for describing other artifacts, such as a zipapp, the same way.

## Command line

```shell
hatch-pep770 spdx dist/example.cdx.json example.spdx.json
hatch-pep770 validate dist/ --allow-license MIT --allow-license Apache-2.0
```

`spdx` renders an SBOM as [SPDX](https://spdx.dev/) 2.3 JSON for tools that read only SPDX. It keeps packages, hashes,
licenses, purls and the relationships, and leaves out per-file hashes (SPDX 2.3 wants a SHA-1 per file, wheel `RECORD`
files hold SHA-256) and the build formulation, which SPDX 2.3 has no field for.

`validate` needs the `validate` extra (`pip install hatch-pep770[validate]`). For each wheel it checks that an SBOM
exists, conforms to the CycloneDX 1.6 schema, carries the `urn:uuid` serial number `actions/attest` needs to recognize
it, has unique and resolvable references, and renders as valid SPDX. With `--allow-license`, every bundled component
must also carry a license the given SPDX ids allow.
