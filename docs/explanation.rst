How it works
============

Architecture
------------

Each concern has its own subpackage, and only the adapters know a build system or the command line. The hatchling hook
and the ``embed`` command gather what the edge knows, then call one pipeline function, :func:`~python_sbom.build_sbom`,
with explicit inputs: the :class:`~python_sbom.SbomRequest` a :class:`~python_sbom.Backend` returns, the
:class:`~python_sbom.SourceTree` and :class:`~python_sbom.BuildFacts` the collectors read, and a
:class:`~python_sbom.ContentProvider`. The model turns those inputs into the document with pure functions. The diagram
follows the imports between the subpackages; an arrow points at what a package imports.

.. mermaid::

    flowchart TB
        subgraph adapters[Adapters]
            hook[hatch<br/>hatchling build hook]
            cli[_cli<br/>embed, spdx, validate]
        end
        generate[_generate<br/>Backend, ContentProvider, build_sbom]
        collect[_collect<br/>settings, build facts, source tree]
        validate[_validate<br/>schema, references, licenses]
        formats[_formats<br/>CycloneDX JSON, SPDX 2.3]
        wheel[_wheel<br/>RECORD rows, archive rewrite]
        model[_model<br/>inputs, types, pure document building]
        hook --> generate
        hook --> collect
        hook --> wheel
        cli --> generate
        cli --> collect
        cli --> validate
        cli --> wheel
        generate --> formats
        generate --> wheel
        generate --> model
        collect --> wheel
        collect --> model
        validate --> formats
        validate --> wheel
        validate --> model
        formats --> model
        wheel --> model
        classDef edge fill:#cfe4ff,stroke:#1f6feb,color:#0b1f3a;
        classDef core fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
        class hook,cli,collect edge;
        class generate,validate,formats,wheel,model core;

The model imports nothing else of the package, and nothing below the adapters imports hatchling, so the library and
the command line work without it. Every package raises subclasses of :class:`~python_sbom.SbomError`, which the command
line reports without a traceback.

Extension points are explicit: a build system plugs in as a :class:`~python_sbom.Backend`, a project adds content as a
:class:`~python_sbom.ContentProvider`, and another version control system as a :class:`~python_sbom.RevisionReader`.
The hatch hook exposes two factories, :meth:`~python_sbom.hatch.SbomBuildHook.content_provider` and
:meth:`~python_sbom.hatch.SbomBuildHook.backend`, for a subclass to override.

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
the build environment with its dependencies, the files and hashes of each pure-Python one, and ``SOURCE_DATE_EPOCH``
when it set the build time.
Property names start with the project's normalized name, such as ``virtualenv:bundled-wheel``, or with ``python:`` for
values copied from core metadata.

Reproducibility
---------------

The document holds nothing about the build machine. Its timestamp comes from ``SOURCE_DATE_EPOCH``. When that is
unset, a reproducible hatchling build uses hatchling's fixed 2020-02-02, the time it stamps on the wheel's entries, and
any other build uses the current time. Its serial number derives from the content, so identical documents share one
and any difference gets a new one.

The build tools are listed down to their files, so a rebuild can check it installed the same bytes. Only what is the
same on every machine goes in: platform wheels appear without their files, because those differ per operating system
and architecture, and editable installs without theirs, because they point at a checkout. Installer metadata,
console-script launchers and uv's cache files are left out too, since they name the frontend, the environment's path or
a time rather than the distribution.

Hashing each tool's ``RECORD`` instead would be smaller, but that file lists the installer metadata, so two frontends
installing the same tools would give two hashes. The cost is size: python-sbom's own isolated build lists about 600
files, half of them from setuptools, which setuptools-scm pulls in, for an SBOM of about 400 KB.

So a rebuild reproduces the wheel byte for byte on any operating system when these match the original build: the
source tree, as a checkout of the same commit; ``SOURCE_DATE_EPOCH``; the Python version; and the versions of the
build backend and its dependencies. The SBOM records the last three, so it says what to install before rebuilding.

Limitations
-----------

- The document describes what the project declares and bundles, not the full tree of runtime dependencies, which
  depends on the environment the wheel is installed into.
- The links to the PyPI release and attestation assume the project publishes to PyPI with attestations.
- A build from an sdist has no git checkout, so its SBOM names no commit unless ``PYTHON_SBOM_COMMIT`` or an expanded
  ``.git_archival.txt`` supplies it.
- ``python-sbom embed`` records the environment ``--build-env`` names, by default the one it runs in. Unless that is
  the environment the wheel was built in, the build tool record does not match the real build.
- The SPDX rendering leaves out per-file hashes and the build record, which SPDX 2.3 cannot hold.
- A tool that renames the wheel after the build, such as ``auditwheel repair``, leaves the attestation link pointing at
  the old file name until ``python-sbom embed`` runs on the renamed wheel.
