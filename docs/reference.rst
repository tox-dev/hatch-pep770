###########
 Reference
###########

********************
 Supported backends
********************

Each build backend gets the SBOM through one integration. :ref:`concepts:Why each backend gets its integration` says why each gets the one it
does.

.. list-table::
    :header-rows: 1

    * - Backend
      - Integration
      - Turned on by
      - Install
      - Guide
    * - hatchling
      - build hook, ``hatch`` entry point group
      - ``[tool.hatch.build.hooks.python-sbom]``
      - ``python-sbom[hatch]``
      - :ref:`how-to:Use it with hatchling`
    * - pdm-backend
      - build hook, ``pdm.build.hook`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[pdm]``
      - :ref:`how-to:Use it with pdm-backend`
    * - setuptools
      - plugin, ``setuptools.finalize_distribution_options`` entry point group
      - ``[tool.python-sbom]``
      - ``python-sbom[setuptools]``
      - :ref:`how-to:Use it with setuptools`
    * - meson-python, maturin, scikit-build-core, flit-core, poetry-core, uv_build
      - ``python_sbom.backend``, which wraps the backend
      - ``[build-system] build-backend = 'python_sbom.backend'`` and ``[tool.python-sbom] build-backend``
      - ``python-sbom``
      - :ref:`how-to:Use it with any other backend`
    * - any, for a wheel built outside the build interface or renamed after it
      - ``python-sbom embed``
      - running the command
      - ``python-sbom``
      - :ref:`how-to:Describe a wheel built outside the build interface`

Every integration writes the same document, from the same ``[tool.python-sbom]`` options, and records the source
revision in the sdists it builds. None writes an SBOM into an editable wheel, which carries no code.

***************
 Configuration
***************

The ``[tool.python-sbom]`` table
================================

The options live in a ``[tool.python-sbom]`` table of the project's ``pyproject.toml``, the one place every plugin, the
wrapper backend, ``python-sbom embed`` and ``python-sbom archive`` read, so every SBOM of a project names it alike. For
the pdm-backend and setuptools plugins, the table's presence, even empty, is what turns them on. Each option is optional;
an unknown key fails the build, so a typo cannot pass silently.

``supplier``
    The organization that supplies the project: a table with a ``name`` string and an optional ``url`` string array. It
    becomes the supplier and manufacturer of the document and the supplier of the project. Left out, the document names
    no supplier.

    .. code-block:: toml

        [tool.python-sbom]
        supplier = { name = 'Python Packaging Authority', url = ['https://www.pypa.io'] }

``repository``
    The repository URL, used for the link to the source revision, the license file and, on GitHub, the security policy
    and advisories. It defaults to the first ``Source``, ``Repository`` or ``GitHub`` URL in ``[project.urls]``.

    .. code-block:: toml

        [tool.python-sbom]
        repository = 'https://gitlab.com/example/project'

``default-branch``
    The branch in links to files of the repository when the build's commit is unknown or the checkout has uncommitted
    changes, ``main`` by default; otherwise the links name the commit.

    .. code-block:: toml

        [tool.python-sbom]
        default-branch = 'trunk'

``bundled-wheels``
    Glob patterns, relative to the project root, of wheels the project ships as data files. Each matching wheel becomes
    a component with its SHA-256, license, files and the packages it vendors.

    .. code-block:: toml

        [tool.python-sbom]
        bundled-wheels = ['src/project/wheels/*.whl']

``content-provider``
    A :class:`~python_sbom.ContentProvider`, as ``module:attribute`` importable from the project root, that adds what
    the project knows beyond its metadata; :ref:`how-to:Add what your project knows` shows one. Loading it imports, and so runs,
    that module.

    .. code-block:: toml

        [tool.python-sbom]
        content-provider = 'sbom_content:Content'

``build-backend``
    The build backend ``python_sbom.backend`` wraps, as ``module`` or ``module:object``, the form ``[build-system]
    build-backend`` takes. Only the wrapper reads it, and it fails the build when the project uses the wrapper without
    it; :ref:`how-to:Use it with any other backend` shows it.

    .. code-block:: toml

        [tool.python-sbom]
        build-backend = 'mesonpy'

.. _bundled-wheels:

Bundled wheels
==============

A bundled wheel's files come from its ``RECORD``, and the build fails when a member is missing from it, a row names a
member the wheel lacks, or a digest differs from the member's content. Its vendored packages come from
``_vendor/vendor.txt``, pip's manifest, whose lines must each pin one exact version, and from any
``.dist-info/METADATA`` under ``_vendor/``. A bundled wheel gets a supplier only from the project's content provider,
never from its own metadata.

Environment variables
=====================

``SOURCE_DATE_EPOCH``
    The document's timestamp, as a Unix time. Unset, a reproducible hatchling build uses hatchling's fixed 2020-02-02,
    a pdm-backend build pdm-backend's fixed 2016-01-01, and any other build the current time.

``PYTHON_SBOM_COMMIT``
    The source revision to record, a full commit hash, for a wheel built from an sdist without
    ``.python-sbom-revision``. It wins over every other source.

.. _source-revision:

The source revision
===================

The SBOM names the commit the wheel was built from. It takes the first source that knows it:

#. the ``PYTHON_SBOM_COMMIT`` environment variable, or ``--commit`` on the command line;
#. git, when the project's ``pyproject.toml`` is tracked by the checkout that holds it, so a project unpacked inside an
   unrelated repository never borrows that repository's commit;
#. ``.python-sbom-revision``, which every integration writes into an sdist built from a clean checkout, so a wheel built
   from the sdist, as ``python -m build`` and ``uv build`` do by default, keeps the commit;
#. the ``node`` line of an expanded ``.git_archival.txt``, for a ``git archive``.

A commit must be a full hash of 40 or 64 hex characters. A checkout with changes, including untracked files that are not
ignored, gets a ``<project>:vcs-dirty`` property, and the link to the revision says so; its sdist records no revision.
When git cannot read the checkout, the build warns and moves on to the next source. git runs with ``core.fsmonitor``
off, so a repository's configuration runs no command.

Validation limits
=================

Before anything else, ``python-sbom validate`` counts the components an SBOM lists, nested ones included, and fails an
SBOM that lists more than ``--max-components``, 100,000 by default, without checking it further. Every check takes time
in proportion to the count: 100,000 files take about a second, and 100,000 packages, each also checked in the SPDX
rendering, about six. The cap bounds what an untrusted SBOM can ask of a CI job while staying far above real SBOMs: every
file of the wheel, of each bundled wheel and of each build tool counts, and virtualenv's wheel lists about 5,200.

The cap also sets the size limit: 1 KiB per component plus 1 MiB, 103,448,576 bytes at the default, about twice the 54
MB python-sbom writes for 100,000 components. ``validate`` refuses a larger SBOM before parsing it, and reads the SBOMs
of a wheel one at a time, so memory holds only one however many the wheel packs. It also refuses an SBOM nested more
than 128 levels deep; the SBOMs python-sbom and other tools write nest about a dozen levels.

************************
 Command line interface
************************

.. sphinx_argparse_cli::
    :module: python_sbom._cli._parser
    :func: build_parser
    :title:
    :group_title_prefix:

************
 Python API
************

The Python API is what a build backend loads and what a project needs to add its own knowledge to the SBOM: the backend
integrations and the content provider they call, with the types those take and return. Everything else, from embedding
to validation, runs through the :ref:`reference:Command line interface`. The core is importable from ``python_sbom`` without any build backend; each
integration lives in a module of its own and imports only its backend.

.. py:data:: python_sbom.__version__
    :type: str

    The installed version of python-sbom.

Backend integrations
====================

.. autoclass:: python_sbom.hatch.SbomBuildHook
    :members: content_provider

.. autoclass:: python_sbom.pdm.SbomBuildHook
    :members: pdm_build_hook_enabled, pdm_build_initialize, pdm_build_update_files, pdm_build_finalize

.. autofunction:: python_sbom.setuptools.finalize_distribution_options

.. autofunction:: python_sbom.backend.build_wheel

.. autofunction:: python_sbom.backend.build_sdist

Content provider
================

.. autoclass:: python_sbom.ContentProvider
    :members: bundled_wheel, contributions

.. autoclass:: python_sbom.ProviderContext
    :members: read

.. autoclass:: python_sbom.BundledWheelInfo

.. autoclass:: python_sbom.Contributions

.. autoclass:: python_sbom.Settings

.. autoclass:: python_sbom.ProjectIdentity

Component types
===============

These :class:`~typing.TypedDict` types describe the JSON a provider builds. Each follows the CycloneDX 1.6 object of the
same name; the `CycloneDX 1.6 reference <https://cyclonedx.org/docs/1.6/json/#components>`_ describes every key.

.. py:class:: python_sbom.Component

    A CycloneDX 1.6 component, a distribution, an application, the interpreter or a file, as a dictionary with the keys
    the CycloneDX component object defines. python-sbom uses ``type``, ``bom-ref``, ``name``, ``version``, ``purl``,
    ``supplier`` (an :class:`~python_sbom.OrganizationalEntity`), ``authors`` (:class:`~python_sbom.Contact`),
    ``description``, ``licenses`` (:class:`~python_sbom.License`), ``copyright``, ``hashes``
    (:class:`~python_sbom.Hash`), ``externalReferences`` (:class:`~python_sbom.ExternalReference`), ``properties``
    (:class:`~python_sbom.Property`), ``evidence`` (:class:`~python_sbom.Evidence`) and the nested ``components``.

.. autoclass:: python_sbom.Property
    :no-members:

.. autoclass:: python_sbom.Dependency
    :no-members:

.. autoclass:: python_sbom.OrganizationalEntity
    :no-members:

.. autoclass:: python_sbom.Contact
    :no-members:

.. autoclass:: python_sbom.ExternalReference
    :no-members:

.. autoclass:: python_sbom.Hash
    :no-members:

.. autoclass:: python_sbom.License
    :no-members:

.. autoclass:: python_sbom.LicenseInfo
    :no-members:

.. autoclass:: python_sbom.Evidence
    :no-members:

.. autoclass:: python_sbom.Identity
    :no-members:

.. autoclass:: python_sbom.IdentityMethod
    :no-members:

Errors
======

.. autoexception:: python_sbom.SbomError
