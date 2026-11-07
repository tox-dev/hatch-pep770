# hatch-pep770

[![PyPI](https://img.shields.io/pypi/v/hatch-pep770?style=flat-square)](https://pypi.org/project/hatch-pep770/)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/hatch-pep770.svg)](https://pypi.org/project/hatch-pep770/)
[![check](https://github.com/tox-dev/hatch-pep770/actions/workflows/check.yaml/badge.svg)](https://github.com/tox-dev/hatch-pep770/actions/workflows/check.yaml)
[![Documentation Status](https://readthedocs.org/projects/hatch-pep770/badge/?version=latest)](https://hatch-pep770.readthedocs.io/en/latest/?badge=latest)
[![Downloads](https://static.pepy.tech/badge/hatch-pep770/month)](https://pepy.tech/project/hatch-pep770)

Write a [CycloneDX](https://cyclonedx.org/) SBOM into every wheel you build, where
[PEP 770](https://peps.python.org/pep-0770/) tells installers to keep it. The SBOM records your project, the runtime
dependencies it declares, any wheels it bundles, and the build toolchain, and a rebuild with the same inputs reproduces
it byte for byte.

## Use

With [hatchling](https://hatch.pypa.io/latest/), add the hook to the build requirements and enable it:

```toml
[build-system]
build-backend = "hatchling.build"
requires = ["hatch-pep770>=0.1", "hatchling>=1.28"]

[tool.hatch.build.hooks.pep770]
```

With another build backend, such as meson-python, embed the SBOM after the build:

```console
hatch-pep770 embed dist/*.whl
```

The [documentation](https://hatch-pep770.readthedocs.io) covers the options, extending the SBOM from a custom build
hook, rendering it as SPDX and validating it.
