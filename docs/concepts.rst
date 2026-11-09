##############
 How it works
##############
This page explains why each build backend gets the integration it does, what the SBOM records and why, and how the code is laid out. The :doc:`how-to` show how to set python-sbom up, and the :doc:`reference` lists the options.

***************************************
 Why each backend gets its integration
***************************************

The SBOM describes the finished wheel: its file name, its files with their hashes, and the environment that built it.
So it has to be written after the backend has written the wheel, inside the build, and every integration is shaped by
where a backend lets code run at that moment.

Plugins where a backend has a hook after the build
==================================================

Three backends let a plugin run once the artifact exists:

- hatchling calls a build hook's ``finalize`` with the wheel's path;
- `pdm-backend <https://backend.pdm-project.org/hooks/>`_ calls ``pdm_build_finalize`` with the artifact's path;
- `setuptools <https://setuptools.pypa.io/en/latest/userguide/extension.html>`_ lets a plugin replace the commands it
  runs, so python-sbom wraps ``bdist_wheel`` and ``sdist``.

A plugin keeps the project's ``build-backend`` as it is and sees the artifact the backend built. hatchling enables a
hook by its table. pdm-backend and setuptools run every plugin installed in the build environment, so python-sbom acts
only for a project with a ``[tool.python-sbom]`` table, and a package that merely has python-sbom installed nearby
builds as before.

A wrapper where a backend has none
==================================

meson-python, maturin, flit-core and uv_build have no plugin interface. poetry-core's build script runs before
packaging, and scikit-build-core has none that runs after the build either; its own documentation recommends `wrapping
the backend <https://scikit-build-core.readthedocs.io/en/latest/configuration/wrapping.html>`_. Static SBOM options, such
as hatchling's ``sbom-files`` or maturin's include list, add a file while the wheel is still being written, too early
for a document that lists the wheel's own hashes.

Every backend shares one interface, though: the hooks of `PEP 517 <https://peps.python.org/pep-0517/>`_ and `PEP 660
<https://peps.python.org/pep-0660/>`_. ``python_sbom.backend`` implements it by handing each call to the backend the
project names, then writing the SBOM into the wheel it returned. It needs no code per backend, so a backend released
later works with it too. It runs in the isolated environment the frontend made for the build, so the SBOM lists the
build tools that ran.

The wrapper exposes an optional hook only when the wrapped backend has it. A frontend checks for an optional hook, such
as ``prepare_metadata_for_build_wheel``, and falls back to its own default when it is missing; a wrapper that defined
every hook would change what the frontend does.

The sdist
=========

A wheel built from an sdist, which is what ``python -m build`` and ``uv build`` do by default, is built outside the git
checkout, so it cannot ask git for its commit. Each integration therefore adds ``.python-sbom-revision``, holding the
commit, to the sdist of a clean checkout. The plugins add it while the backend writes the sdist; the wrapper adds it to
the finished archive, keeping the backend's own times so a reproducible sdist stays reproducible.

What still runs after the build
===============================

Two things sit outside every backend:

- Tools that build without the build interface, such as ``maturin build`` in maturin-action, never call a plugin or the
  wrapper.
- ``auditwheel repair`` and ``delocate`` run after the build and rename the wheel, so a document written during the
  build names a file that is never published.

``python-sbom embed`` covers both: it describes a finished wheel from the outside. It cannot see the build environment,
so it records the one it runs in, or the one ``--build-env`` names; :ref:`how-to:Describe a wheel built outside the build interface` shows how to make
that the real one.

***********************
 What the SBOM records
***********************

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

.. _reproducibility:

Reproducibility
===============

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
===========

- The document describes what the project declares and bundles, not the full tree of runtime dependencies, which depends
  on the environment the wheel is installed into.
- The links to the PyPI release and attestation assume the project publishes to PyPI with attestations.
- A wheel built from an sdist of a dirty checkout names no commit, since no commit reproduces it.
- ``python-sbom embed`` and ``archive`` record the packages of the environment ``--build-env`` names, by default the one
  they run in, and always the interpreter they run on. Unless that is the environment the artifact was built in, the
  build tool record does not match the real build.
- The SPDX rendering leaves out per-file hashes and the build record, which SPDX 2.3 cannot hold.
- A tool that renames the wheel after the build, such as ``auditwheel repair``, leaves the attestation link pointing at
  the old file name until ``python-sbom embed`` runs on the renamed wheel; :ref:`concepts:Why each backend gets its integration` says why.

**************
 Architecture
**************

Each concern has its own subpackage, and only the adapters know a build system or the command line. The build backend
integrations (the hatchling and pdm-backend hooks, the setuptools plugin and the wrapper backend) and the ``embed`` and
``archive`` commands gather the options, the build scripts and the build facts (time, revision,
toolchain), and hand them, with a :class:`~python_sbom.ContentProvider`, to the pipeline for their artifact. Each
pipeline opens its artifact once, reads it, gives the provider a :class:`~python_sbom.ProviderContext` that reads from
the same open artifact, and maps what it read to components; one function of the model then adds what every artifact
of the project shares: supplier, source links, revision, tools, dependencies and formulation.

The diagram follows one build, from the entry point to the document written into the artifact:

.. mermaid::

    flowchart LR
        entry["Entry point<br/>build hook, plugin, wrapper backend,<br/>embed or archive command"]
        collect["Collect<br/>options, revision,<br/>build tools, artifact"]
        provider["Content provider<br/>what the project adds"]
        model["Model<br/>the CycloneDX document"]
        write["Write<br/>into the wheel or archive"]
        entry --> collect --> model --> write
        provider --> model
        classDef io fill:#cfe4ff,stroke:#1f6feb,color:#0b1f3a;
        classDef core fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
        class entry,write io;
        class collect,provider,model core;

Each step lives in a subpackage of its own:

.. list-table::
    :header-rows: 1

    * - Subpackage
      - Responsibility
    * - ``hatch``, ``pdm``, ``setuptools``, ``backend``, ``_cli``
      - the entry points; only these know a build backend or the command line
    * - ``_generate``
      - one pipeline per artifact, wheel or archive, which runs the steps below in order
    * - ``_collect``
      - reads the options, the source revision, the build environment and the artifact's files
    * - ``_model``
      - turns what was read into the document; pure functions, no file access
    * - ``_formats``
      - writes the document as CycloneDX JSON, or renders it as SPDX 2.3
    * - ``_wheel``, ``_backends``
      - read and rewrite zip files and sdists
    * - ``_validate``
      - checks finished SBOMs, for the ``validate`` command

Every subpackage raises :class:`~python_sbom.SbomError`, which the command line reports without a traceback. Each
integration imports its own build backend and nothing else does, so the provider API and the command line work without
any backend installed.

The one extension point is the :class:`~python_sbom.ContentProvider`, which every entry point loads from the
``content-provider`` option. A hatchling custom hook can override
:meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to build the provider itself.
