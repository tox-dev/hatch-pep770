##############
 Architecture
##############

Each concern has its own subpackage, and only the adapters know a build system or the command line. The build backend
integrations (the hatchling and pdm-backend hooks, the setuptools plugin and the wrapper backend) and the ``embed`` and
``archive`` commands gather the options, the build scripts and the build facts (time, revision, toolchain), and hand
them, with a :class:`~python_sbom.ContentProvider`, to the pipeline for their artifact. Each pipeline opens its artifact
once, reads it, gives the provider a :class:`~python_sbom.ProviderContext` that reads from the same open artifact, and
maps what it read to components; one function of the model then adds what every artifact of the project shares:
supplier, source links, revision, tools, dependencies and formulation.

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

    - - Subpackage
      - Responsibility
    - - ``hatch``, ``pdm``, ``setuptools``, ``backend``, ``_cli``
      - the entry points; only these know a build backend or the command line
    - - ``_generate``
      - one pipeline per artifact, wheel or archive, which runs the steps below in order
    - - ``_collect``
      - reads the options, the source revision, the build environment and the artifact's files
    - - ``_model``
      - turns what was read into the document; pure functions, no file access
    - - ``_formats``
      - writes the document as CycloneDX JSON, or renders it as SPDX 2.3
    - - ``_wheel``, ``_backends``
      - read and rewrite zip files and sdists
    - - ``_validate``
      - checks finished SBOMs, for the ``validate`` command

Every subpackage raises :class:`~python_sbom.SbomError`, which the command line reports without a traceback. Each
integration imports its own build backend and nothing else does, so the provider API and the command line work without
any backend installed.

The one extension point is the :class:`~python_sbom.ContentProvider`, which every entry point loads from the
``content-provider`` option. A hatchling custom hook can override
:meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to build the provider itself.
