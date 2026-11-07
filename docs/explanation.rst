How it works
============

What the SBOM records
---------------------

The document's root component is the project, described from the wheel's ``METADATA``: name, version, summary,
license expression, maintainers, project URLs, classifiers and keywords. Links to the PyPI release, the wheel's
attestation and, with a repository, the license file follow. A build from a git checkout adds the commit and a link to
that exact revision.

The components below the root are the wheels the project bundles and the runtime dependencies it declares. A bundled
wheel carries its SHA-256, its license, a component per file from its ``RECORD``, and the packages it vendors. A
declared dependency carries no version, because the installer picks it at install time; the document marks the root's
dependencies incomplete for that reason. An extra's dependencies are left out.

The formulation records how the wheel was built: the interpreter's version and implementation, every distribution of
the build environment with its dependencies, the files and hashes of each pure-Python one, and ``SOURCE_DATE_EPOCH``.
Property names start with the project's normalized name, such as ``virtualenv:bundled-wheel``, or with ``python:`` for
values copied from core metadata.

Reproducibility
---------------

The document holds nothing about the build machine. Its timestamp comes from ``SOURCE_DATE_EPOCH``, or hatchling's
fixed default of 2020-02-02 when that is unset. Its serial number derives from the content, so identical documents
share one and any difference gets a new one. Platform wheels in the build environment appear without their files,
because those differ per operating system and architecture. Installer metadata and console-script launchers are left
out too, since they name the frontend and the environment's path rather than the distribution.

So a rebuild reproduces the wheel byte for byte on any operating system when these match the original build: the
source tree, as a checkout of the same commit; ``SOURCE_DATE_EPOCH``; the Python version; and the versions of the
build backend and its dependencies. The SBOM records the last three, so it says what to install before rebuilding.

Limitations
-----------

- The document describes what the project declares and bundles, not the full tree of runtime dependencies, which
  depends on the environment the wheel is installed into.
- The links to the PyPI release and attestation assume the project publishes to PyPI with attestations.
- A build from an sdist has no git checkout, so its SBOM names no commit.
- ``python-sbom embed`` records the environment it runs in. Unless the wheel was built without isolation in that
  environment, the build tool record does not match the real build.
- The SPDX rendering leaves out per-file hashes and the build record, which SPDX 2.3 cannot hold.
- A hook that changes the wheel tag after this one runs leaves the attestation link pointing at the wrong file name.
