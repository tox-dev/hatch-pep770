What the SBOM records
=====================

The document's root component is the project, described from the wheel's ``METADATA``: name, version, summary, license
expression, maintainers, project URLs, classifiers and keywords. Links to the PyPI release, the wheel's attestation and,
with a repository, the license file follow. A build from a git checkout adds the commit and a link to that exact
revision. Links to the license file and build scripts point at that commit when the checkout is clean, and at the
default branch otherwise.

CycloneDX requires each URL to be an IRI reference. A project URL or home page that is not one gets percent-encoded,
or left out when encoding cannot mend it, as with an scp-style ``git@host:path`` address; either way a
``python:project-url`` or ``python:home-page`` property keeps the text as written.

The components below the root are the wheels the project bundles and the runtime dependencies it declares. A bundled
wheel carries its SHA-256, its license, a component per file from its ``RECORD``, and the packages it vendors. A
declared dependency carries no version, because the installer picks it at install time; the document marks the root's
dependencies incomplete for that reason. An extra's dependencies are left out.

The formulation records how the wheel was built: the interpreter's version and implementation, every distribution of the
build environment with its dependencies, the files and hashes of each pure-Python one, and ``SOURCE_DATE_EPOCH`` when it
set the build time.

Property names start with the project's normalized name, such as ``virtualenv:bundled-wheel``, or with ``python:`` for
values copied from core metadata.

Reproducibility
---------------

The document holds nothing about the build machine. Its timestamp comes from ``SOURCE_DATE_EPOCH``. When that is unset,
a reproducible hatchling build uses hatchling's fixed 2020-02-02 and a pdm-backend build pdm-backend's fixed
2016-01-01, the times they stamp on the wheel's entries, and any other build uses the current time. Its serial number derives from the content, so identical documents share one and any
difference gets a new one.

The build tools are listed down to their files, so a rebuild can check it installed the same bytes. Only what is the
same on every machine goes in: platform wheels appear without their files, because those differ per operating system and
architecture, and editable installs without theirs, because they point at a checkout. Installer metadata, console-script
launchers and uv's cache files are left out too, since they name the frontend, the environment's path or a time rather
than the distribution.

Hashing each tool's ``RECORD`` instead would be smaller, but that file lists the installer metadata, so two frontends
installing the same tools would give two hashes. The cost is size: the file list grows with the build environment, and
a large build tool such as setuptools adds hundreds of entries.

So a rebuild reproduces the wheel byte for byte on any operating system when these match the original build: the source
tree, as a checkout of the same commit; ``SOURCE_DATE_EPOCH``; the Python version; and the versions of the build backend
and its dependencies. The SBOM records the last three, so it says what to install before rebuilding.

Limitations
-----------

- The document describes what the project declares and bundles, not the full tree of runtime dependencies, which depends
  on the environment the wheel is installed into.
- The links to the PyPI release and attestation assume the project publishes to PyPI with attestations.
- A wheel built from an sdist of a dirty checkout names no commit, since no commit reproduces it.
- ``python-sbom embed`` and ``archive`` record the packages of the environment ``--build-env`` names, by default the one
  they run in, and always the interpreter they run on. Unless that is the environment the artifact was built in, the
  build tool record does not match the real build.
- The SPDX rendering leaves out per-file hashes and the build record, which SPDX 2.3 cannot hold.
- A tool that renames the wheel after the build, such as ``auditwheel repair``, leaves the attestation link pointing at
  the old file name until ``python-sbom embed`` runs on the renamed wheel; :doc:`backends` says why.
