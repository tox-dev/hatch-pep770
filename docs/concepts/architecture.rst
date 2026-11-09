##############
 Architecture
##############

Only the entry points know a build system or the command line: the hatchling and pdm-backend hooks, the setuptools
plugin, the wrapper backend, and the ``embed`` and ``archive`` commands. Each gathers the options, the build scripts and
the build facts (time, revision, toolchain) and hands them, with a :class:`~python_sbom.ContentProvider`, to the
pipeline for its artifact. The pipeline opens the artifact once, reads it, gives the provider a
:class:`~python_sbom.ProviderContext` that reads from the same open artifact, and maps what it read to components. It
then adds what every artifact of the project shares: supplier, source links, revision, tools, dependencies and
formulation.

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

Every step raises :class:`~python_sbom.SbomError`, which the command line reports without a traceback. Each
integration imports its own build backend and nothing else does, so the provider API and the command line work without
any backend installed.

The one extension point is the :class:`~python_sbom.ContentProvider`, which every entry point loads from the
``content-provider`` option. A hatchling custom hook can override
:meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to build the provider itself.
