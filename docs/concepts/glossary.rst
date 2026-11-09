##########
 Glossary
##########

A :term:`build frontend` asks a :term:`build backend` for a :term:`wheel`. python-sbom runs inside that build, through a
:term:`build hook` or the :term:`wrapper backend`, and writes an :term:`SBOM` into the wheel where :term:`PEP 770` tells
installers to look. The SBOM is a :term:`CycloneDX` document. It names the :term:`supplier`, lists each
:term:`component` the wheel holds or declares, and records in its :term:`formulation` the :term:`source revision` and
the build tools, the facts a :term:`reproducible build` needs. A :term:`content provider` adds what python-sbom cannot
read from the wheel. :term:`Validation <validation>` checks the document before upload, and python-sbom renders it as
:term:`SPDX` for tools that read only that format.

.. glossary::
    :sorted:

    archive
        A zip file other than a wheel that holds distributions, unpacked or as wheels, such as a zipapp. python-sbom
        describes it the way it describes a :term:`wheel`.

    build backend
        The tool that turns a project's source into a :term:`wheel` and an :term:`sdist`, such as hatchling, setuptools
        or maturin. A :term:`build frontend` calls it through the interface PEP 517 defines.

    build frontend
        The tool a user runs to build or install a project, such as pip, uv or build. It installs the :term:`build
        backend` in an isolated environment and asks it for the artifacts.

    build hook
        A plugin a :term:`build backend` calls during its own build. python-sbom has one for hatchling, pdm-backend and
        setuptools, and writes the :term:`SBOM` before the backend finishes the :term:`wheel`.

    bundled wheel
        A wheel a project ships as a data file inside its own :term:`wheel`, as virtualenv ships pip. The :term:`SBOM`
        lists it as a :term:`component` with its hashes, license, files and :term:`vendored packages <vendored
        package>`.

    component
        One entry in the :term:`SBOM`: the project itself, a file, a :term:`bundled wheel`, a declared dependency or a
        build tool.

    content provider
        A class a project writes to add components and properties python-sbom cannot read from the artifact. Every
        integration loads the one the project's configuration names.

    CycloneDX
        The SBOM format python-sbom writes, version 1.6, as JSON.

    formulation
        The part of a :term:`CycloneDX` document that records how the artifact was made: the build workflow, the tools
        it used, and the build time when the environment set it.

    PEP 770
        The standard that gives a :term:`wheel` a folder for SBOMs in its metadata directory, so installers copy them
        into the environment where scanners look.

    reproducible build
        A build that yields the same bytes from the same source and tools. The :term:`SBOM` records the :term:`source
        revision` and each build tool with its files, so a third party can rebuild the :term:`wheel` and compare.

    SBOM
        A software bill of materials: a document that lists what a piece of software contains and how it was built.

    sdist
        A source distribution: the archive of a project's source from which a :term:`build backend` builds a
        :term:`wheel` later. python-sbom stores the :term:`source revision` in it, so a wheel built from it still names
        its commit.

    source revision
        The commit a build ran from, and whether the checkout had uncommitted changes.

    SPDX
        Another SBOM format. python-sbom renders the :term:`CycloneDX` document as SPDX 2.3 on request.

    supplier
        The organization that ships the project. The configuration names it, and the :term:`SBOM` records it as the
        document's supplier and manufacturer.

    validation
        The check of a finished :term:`SBOM` against the :term:`CycloneDX` schema, its own references and an optional
        license policy, meant to run in CI before upload.

    vendored package
        A package copied into another package's source instead of installed as a dependency. The :term:`SBOM` lists it
        under the :term:`bundled wheel` that carries it.

    wheel
        The built distribution an installer unpacks into an environment, and the file python-sbom writes the
        :term:`SBOM` into.

    wrapper backend
        python-sbom's own :term:`build backend`, which passes each call to the backend the project names and adds the
        :term:`SBOM` to the :term:`wheel` it gets back. It serves backends without a :term:`build hook`.
