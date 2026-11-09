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

## Use

python-sbom works with every build backend. Pick the integration for yours:

| Backend                                                                  | Add to `[build-system] requires` | Turn it on                                                                        |
| ------------------------------------------------------------------------ | -------------------------------- | --------------------------------------------------------------------------------- |
| [hatchling](https://hatch.pypa.io/latest/)                               | `python-sbom[hatch]`             | `[tool.hatch.build.hooks.python-sbom]`                                            |
| [pdm-backend](https://backend.pdm-project.org/)                          | `python-sbom[pdm]`               | `[tool.python-sbom]`                                                              |
| [setuptools](https://setuptools.pypa.io/)                                | `python-sbom[setuptools]`        | `[tool.python-sbom]`                                                              |
| any other, such as meson-python, maturin, scikit-build-core or flit-core | `python-sbom`                    | `build-backend = "python_sbom.backend"`, and your backend in `[tool.python-sbom]` |

With hatchling:

```toml
[build-system]
build-backend = "hatchling.build"
requires = ["hatchling>=1.28", "python-sbom[hatch]>=0.2"]

[tool.hatch.build.hooks.python-sbom]
```

With meson-python, or any backend without a plugin, python-sbom wraps it:

```toml
[build-system]
build-backend = "python_sbom.backend"
requires = ["meson-python>=0.18", "python-sbom>=0.2"]

[tool.python-sbom]
build-backend = "mesonpy"
```

For a wheel built outside the build interface, such as with `maturin build`, or renamed after it by `auditwheel repair`,
embed the SBOM afterwards:

```console
python-sbom embed dist/*.whl
```

To convert and validate SBOMs in CI, install the command line in a tool environment of its own:

```console
pipx install 'python-sbom[validate]'
python-sbom validate dist/
```

The [documentation](https://python-sbom.readthedocs.io) starts with a tutorial, then has a guide per backend, the
options and commands, and how the SBOM is built. It also covers describing a zipapp, adding project knowledge through a
content provider, and rendering an SBOM as SPDX.
