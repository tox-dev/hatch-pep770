# python-sbom

[![PyPI](https://img.shields.io/pypi/v/python-sbom?style=flat-square)](https://pypi.org/project/python-sbom/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/python-sbom.svg)](https://pypi.org/project/python-sbom/)
[![check](https://github.com/tox-dev/python-sbom/actions/workflows/check.yaml/badge.svg)](https://github.com/tox-dev/python-sbom/actions/workflows/check.yaml)
[![Documentation Status](https://readthedocs.org/projects/python-sbom/badge/?version=latest)](https://python-sbom.readthedocs.io/en/latest/?badge=latest)
[![Downloads](https://static.pepy.tech/badge/python-sbom/month)](https://pepy.tech/project/python-sbom)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tox-dev/python-sbom/badge)](https://scorecard.dev/viewer/?uri=github.com/tox-dev/python-sbom)

SBOMs for Python distributions. python-sbom writes a [CycloneDX](https://cyclonedx.org/) SBOM into every wheel you
build, where [PEP 770](https://peps.python.org/pep-0770/) tells installers to keep it. The SBOM records your project,
the runtime dependencies it declares, any wheels it bundles, and the build toolchain, and a rebuild with the same inputs
reproduces it byte for byte.

## Install

The command line, to embed, convert and validate SBOMs:

```console
pipx install 'python-sbom[validate]'
```

A hatchling project names `python-sbom[hatch]` in its build requirements instead, as shown below.

## Use

With [hatchling](https://hatch.pypa.io/latest/), add the hook to the build requirements and enable it:

```toml
[build-system]
build-backend = "hatchling.build"
requires = ["hatchling>=1.28", "python-sbom[hatch]>=0.1"]

[tool.hatch.build.hooks.python-sbom]
```

With another build backend, such as meson-python, embed the SBOM after the build:

```console
python-sbom embed dist/*.whl
```

The [documentation](https://python-sbom.readthedocs.io) covers the options, extending the SBOM from a custom build hook,
rendering it as SPDX and validating it.
