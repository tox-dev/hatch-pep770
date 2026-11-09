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

    API
        Application programming interface. Here, the Python classes and functions python-sbom publishes for
        :term:`content providers <content provider>` and build integrations, listed in :doc:`/reference/api`.

    archive
        A zip file other than a wheel that holds distributions, unpacked or as wheels, such as a :term:`zipapp`.
        python-sbom describes it the way it describes a :term:`wheel`.

    build backend
        The tool that turns a project's source into a :term:`wheel` and an :term:`sdist`, such as `hatchling`_,
        `setuptools`_ or `maturin`_. A :term:`build frontend` calls it through the interface :term:`PEP 517` defines.

    build frontend
        The tool a user runs to build or install a project, such as `pip`_, `uv`_ or `build
        <https://build.pypa.io/>`_. It installs the :term:`build backend` in an isolated environment and asks it for
        the artifacts.

    build hook
        A plugin a :term:`build backend` calls during its own build. python-sbom has one for `hatchling`_,
        `pdm-backend`_ and `setuptools`_, and writes the :term:`SBOM` before the backend finishes the :term:`wheel`.

    bundled wheel
        A wheel a project ships as a data file inside its own :term:`wheel`, as `virtualenv`_ ships pip. The
        :term:`SBOM` lists it as a :term:`component` with its hashes, license, files and :term:`vendored packages
        <vendored package>`.

    CI
        Continuous integration: the automated jobs, such as `GitHub Actions <https://docs.github.com/en/actions>`_
        workflows, that build, test and publish a project on each change.

    component
        One entry in the :term:`SBOM`: the project itself, a file, a :term:`bundled wheel`, a declared dependency or a
        build tool.

    content provider
        A class a project writes to add components and properties python-sbom cannot read from the artifact. Every
        integration loads the one the project's configuration names.

    CycloneDX
        The `CycloneDX <https://cyclonedx.org/>`_ SBOM standard, which python-sbom writes in version 1.6 as :term:`JSON`.

    formulation
        The part of a :term:`CycloneDX` document that records how the artifact was made: the build workflow, the tools
        it used, and the build time when the environment set it.

    IRI
        Internationalized Resource Identifier, defined by `RFC 3987 <https://www.rfc-editor.org/rfc/rfc3987>`_: a
        :term:`URL` that may hold any Unicode character. CycloneDX requires every link to be one.

    JSON
        JavaScript Object Notation, the `text format <https://www.json.org/>`_ CycloneDX and SPDX documents use.

    PEP 517
        The `Python Enhancement Proposal <https://peps.python.org/pep-0517/>`_ that defines the interface between a
        :term:`build frontend` and a :term:`build backend`.

    PEP 660
        The `Python Enhancement Proposal <https://peps.python.org/pep-0660/>`_ that adds editable installs to the
        interface of :term:`PEP 517`.

    PEP 770
        The `Python Enhancement Proposal <https://peps.python.org/pep-0770/>`_ that gives a :term:`wheel` a folder for
        SBOMs in its metadata directory, so installers copy them into the environment where scanners look.

    PyPI
        The `Python Package Index <https://pypi.org/>`_, where projects publish their wheels and sdists.

    reproducible build
        A build that yields the same bytes from the same source and tools, as `Reproducible Builds
        <https://reproducible-builds.org/>`_ defines it. The :term:`SBOM` records the :term:`source revision` and each
        build tool with its files, so a third party can rebuild the :term:`wheel` and compare.

    SBOM
        Software bill of materials: a document that lists what a piece of software contains and how it was built.

    sdist
        Source distribution: the `archive of a project's source
        <https://packaging.python.org/en/latest/specifications/source-distribution-format/>`_ from which a :term:`build
        backend` builds a :term:`wheel` later. python-sbom stores the :term:`source revision` in it, so a wheel built
        from it still names its commit.

    SHA-1
        Secure Hash Algorithm 1, an older `hash function <https://www.rfc-editor.org/rfc/rfc3174>`_ that SPDX 2.3
        requires for every file.

    SHA-256
        The 256-bit variant of Secure Hash Algorithm 2, the `hash function <https://www.rfc-editor.org/rfc/rfc6234>`_
        a wheel's file list records for each file and the SBOM copies, so anyone can check the bytes.

    source revision
        The commit a build ran from, and whether the checkout had uncommitted changes.

    SPDX
        Software Package Data Exchange, another `SBOM standard <https://spdx.dev/>`_. python-sbom renders the
        :term:`CycloneDX` document as SPDX 2.3 on request.

    supplier
        The organization that ships the project. The configuration names it, and the :term:`SBOM` records it as the
        document's supplier and manufacturer.

    URL
        Uniform Resource Locator: a web address.

    validation
        The check of a finished :term:`SBOM` against the :term:`CycloneDX` schema, its own references and an optional
        license policy, meant to run in :term:`CI` before upload.

    vendored package
        A package copied into another package's source instead of installed as a dependency. The :term:`SBOM` lists it
        under the :term:`bundled wheel` that carries it.

    wheel
        The `built distribution <https://packaging.python.org/en/latest/specifications/binary-distribution-format/>`_
        an installer unpacks into an environment, and the file python-sbom writes the :term:`SBOM` into.

    wrapper backend
        python-sbom's own :term:`build backend`, which passes each call to the backend the project names and adds the
        :term:`SBOM` to the :term:`wheel` it gets back. It serves backends without a :term:`build hook`.

    zipapp
        A Python application packed into one zip file that the interpreter runs directly, as the `zipapp
        <https://docs.python.org/3/library/zipapp.html>`_ module builds it.
