###############
 Configuration
###############

**********************************
 The ``[tool.python-sbom]`` table
**********************************

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
    the project knows beyond its metadata; :doc:`/how-to/content-provider` shows one. Loading it imports, and so runs,
    that module.

    .. code-block:: toml

        [tool.python-sbom]
        content-provider = 'sbom_content:Content'

``build-backend``
    The build backend ``python_sbom.backend`` wraps, as ``module`` or ``module:object``, the form ``[build-system]
    build-backend`` takes. Only the wrapper reads it, and it fails the build when the project uses the wrapper without
    it; :doc:`/how-to/other-backends` shows it.

    .. code-block:: toml

        [tool.python-sbom]
        build-backend = 'mesonpy'

.. _bundled-wheels:

****************
 Bundled wheels
****************

A bundled wheel's files come from its ``RECORD``, and the build fails when a member is missing from it, a row names a
member the wheel lacks, or a digest differs from the member's content. Its vendored packages come from
``_vendor/vendor.txt``, pip's manifest, whose lines must each pin one exact version, and from any
``.dist-info/METADATA`` under ``_vendor/``. A bundled wheel gets a supplier only from the project's content provider,
never from its own metadata.

***********************
 Environment variables
***********************

``SOURCE_DATE_EPOCH``
    The document's timestamp, as a Unix time. Unset, a reproducible hatchling build uses hatchling's fixed 2020-02-02,
    a pdm-backend build pdm-backend's fixed 2016-01-01, and any other build the current time.

``PYTHON_SBOM_COMMIT``
    The source revision to record, a full commit hash, for a wheel built from an sdist without
    ``.python-sbom-revision``. It wins over every other source.

.. _source-revision:

*********************
 The source revision
*********************

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

*******************
 Validation limits
*******************

Before anything else, ``python-sbom validate`` counts the components an SBOM lists, nested ones included, and fails an
SBOM that lists more than ``--max-components``, 100,000 by default, without checking it further. Every check takes time
in proportion to the count: 100,000 files take about a second, and 100,000 packages, each also checked in the SPDX
rendering, about six. The cap bounds what an untrusted SBOM can ask of a CI job while staying far above real SBOMs: every
file of the wheel, of each bundled wheel and of each build tool counts, and virtualenv's wheel lists about 5,200.

The cap also sets the size limit: 1 KiB per component plus 1 MiB, 103,448,576 bytes at the default, about twice the 54
MB python-sbom writes for 100,000 components. ``validate`` refuses a larger SBOM before parsing it, and reads the SBOMs
of a wheel one at a time, so memory holds only one however many the wheel packs. It also refuses an SBOM nested more
than 128 levels deep; the SBOMs python-sbom and other tools write nest about a dozen levels.
