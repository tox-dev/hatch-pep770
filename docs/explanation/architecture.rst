Architecture
============

Each concern has its own subpackage, and only the adapters know a build system or the command line. The build backend
integrations (the hatchling and pdm-backend hooks, the setuptools plugin and the wrapper backend) and the ``embed`` and
``archive`` commands gather the options, the build scripts and the build facts (time, revision,
toolchain), and hand them, with a :class:`~python_sbom.ContentProvider`, to the pipeline for their artifact. Each
pipeline opens its artifact once, reads it, gives the provider a :class:`~python_sbom.ProviderContext` that reads from
the same open artifact, and maps what it read to components; one function of the model then adds what every artifact
of the project shares: supplier, source links, revision, tools, dependencies and formulation.

The diagram follows the imports between the subpackages: a solid arrow points at what a package imports when it loads, a
dotted arrow labeled *lazy* at what it imports only once a function needs it, and a dotted arrow labeled *types* at
what it imports only for type annotations. The command line loads each command's module, and what it imports, only when
that command runs.

.. mermaid::

    flowchart TB
        subgraph adapters[Adapters]
            hook[hatch<br/>hatchling build hook]
            plugins[pdm, setuptools, backend<br/>pdm-backend hook, setuptools plugin, wrapper backend]
            cli[_cli<br/>embed, archive, spdx, validate]
        end
        api[python_sbom<br/>provider API, __main__]
        generate[_generate<br/>wheel and archive pipelines]
        collect[_collect<br/>settings, facts, revision, project tree, wheels, archives, providers]
        validate[_validate<br/>limits, schema, references, licenses]
        formats[_formats<br/>CycloneDX JSON, SPDX 2.3]
        wheel[_wheel<br/>artifact reader, zip reads and writes, RECORD, bundled wheel checks]
        model[_model<br/>inputs, types, identity, graph rules, document building]
        errors[_errors<br/>SbomError]
        sdist[_backends<br/>adding the revision to a finished sdist]
        version[version]
        hook --> collect
        hook -. lazy .-> generate
        hook -. types .-> model
        plugins --> collect
        plugins -. lazy .-> generate
        plugins -. lazy .-> sdist
        plugins -. types .-> model
        cli --> generate
        cli --> validate
        cli --> formats
        cli --> version
        cli -. types .-> model
        api --> cli
        api --> model
        generate --> collect
        generate --> formats
        generate --> wheel
        generate --> model
        collect --> wheel
        collect --> model
        validate --> formats
        validate --> wheel
        validate --> model
        formats --> model
        formats --> version
        model --> errors
        sdist --> errors
        wheel --> model
        classDef edge fill:#cfe4ff,stroke:#1f6feb,color:#0b1f3a;
        classDef core fill:#d8f3dc,stroke:#2d6a4f,color:#081c15;
        class hook,plugins,cli,collect,api edge;
        class generate,validate,formats,wheel,model,errors,version,sdist core;

Every package raises :class:`~python_sbom.SbomError`, which the command line reports without a traceback; the diagram
draws only the model's and ``_backends``' imports of it. Only each integration imports its backend, so the provider
API and the command line work without any of them.

The one extension point is the :class:`~python_sbom.ContentProvider`, which every entry point loads from the
``content-provider`` option. A hatchling custom hook can override
:meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to build the provider itself.
