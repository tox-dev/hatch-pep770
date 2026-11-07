Use it
======

With hatchling
--------------

Add the hook to ``build-system.requires`` and enable it with an empty table, as the quick start on the :doc:`index`
shows. The ``hatch`` extra brings hatchling; the command line needs none. The hook writes the SBOM into wheels only: an
editable wheel carries none, and an sdist carries the source revision instead, so a wheel built from it still names its
commit.

The hook writes the SBOM once hatchling has written the wheel, so the document describes the final file name and
metadata, whatever dependencies or tag other hooks changed. Hatchling runs the hooks in the order of their tables; see
its `build hook documentation <https://hatch.pypa.io/latest/config/build/#build-hooks>`_. The order does not matter for
this hook.

Options
~~~~~~~

The options live in a ``[tool.python-sbom]`` table, the one place the hook, ``python-sbom embed`` and ``python-sbom
archive`` all read, so every SBOM of a project names it alike. Each option is optional; an unknown key fails the build,
so a typo cannot pass silently. The hook's own table holds only hatchling's options, and a python-sbom option there
fails the build with a pointer to ``[tool.python-sbom]``.

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
    The branch in links to files of the repository, ``main`` by default.

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
    the project knows beyond its metadata; :doc:`extend` shows one. Loading it imports, and so runs, that module.

    .. code-block:: toml

        [tool.python-sbom]
        content-provider = 'sbom_content:Content'

A bundled wheel's files come from its ``RECORD``, and the build fails when a member is missing from it, a row names a
member the wheel lacks, or a digest differs from the member's content. Its vendored packages come from
``_vendor/vendor.txt``, pip's manifest, whose lines must each pin one exact version, and from any
``.dist-info/METADATA`` under ``_vendor/``. A bundled wheel gets a supplier only from the project's content provider,
never from its own metadata.

The source revision
~~~~~~~~~~~~~~~~~~~

The SBOM names the commit the wheel was built from. It takes the first source that knows it:

#. the ``PYTHON_SBOM_COMMIT`` environment variable, or ``--commit`` on the command line;
#. git, when the project's ``pyproject.toml`` is tracked by the checkout that holds it, so a project unpacked inside an
   unrelated repository never borrows that repository's commit;
#. ``.python-sbom-revision``, which the hook writes into every sdist built from a clean checkout, so a wheel built from
   the sdist, as ``python -m build`` and ``uv build`` do by default, keeps the commit;
#. the ``node`` line of an expanded ``.git_archival.txt``, for a ``git archive``.

A commit must be a full hash of 40 or 64 hex characters. A checkout with changes, including untracked files that are not
ignored, gets a ``<project>:vcs-dirty`` property, and the link to the revision says so. When git cannot read the
checkout, the build warns and moves on to the next source. git runs with ``core.fsmonitor`` off, so a repository's
configuration runs no command.

With another build backend
--------------------------

A backend other than hatchling, such as `meson-python <https://mesonbuild.com/meson-python/>`_, cannot run the hook.
``python-sbom embed`` writes the same document into a wheel that backend built, adds the ``RECORD`` row, and keeps every
other entry of the archive as it was. It reads the options from ``[tool.python-sbom]``:

.. code-block:: toml

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Build, then embed, from the project root:

.. code-block:: console

    $ python -m build --wheel
    $ python-sbom embed dist/*.whl
    wrote turbohtml-1.0.dist-info/sboms/turbohtml.cdx.json into turbohtml-1.0-cp314-cp314-linux_x86_64.whl

``--commit`` names the source revision when the wheel came from an sdist, and ``--content-provider`` overrides the
``content-provider`` option.

The build tool record lists the packages of the environment named by ``--build-env``, by default the one ``embed`` runs
in; the interpreter it records is always the one running ``embed``. To record the real toolchain, build without
isolation in the environment ``embed`` runs in, from the same lock. On Linux, meson-python also needs ``patchelf``
there:

.. code-block:: console

    $ python -m pip install build python-sbom meson-python meson ninja patchelf
    $ python -m build --wheel --no-isolation
    $ python-sbom embed dist/*.whl

``auditwheel repair`` renames a Linux wheel to its ``manylinux`` tag, so the attestation link in an SBOM written before
the repair names the old file. Run ``embed`` on the repaired wheel, after ``auditwheel``, to describe the file you
publish; auditwheel's own SBOM in the same directory stays untouched.

Render it as SPDX
-----------------

Some tools read only `SPDX <https://spdx.dev/>`_. ``python-sbom spdx`` renders the CycloneDX document as SPDX 2.3 JSON:

.. code-block:: console

    $ unzip -p dist/project-1.0-py3-none-any.whl '*/sboms/project.cdx.json' > project.cdx.json
    $ python-sbom spdx project.cdx.json project.spdx.json

The SPDX document keeps the packages, their hashes, licenses and purls, and the containment, dependency and build tool
relationships. It leaves out the per-file hashes, because SPDX 2.3 wants a SHA-1 for every file and wheel ``RECORD``
files hold SHA-256, and the build record, which SPDX 2.3 has no field for. Its namespace ends in the CycloneDX serial
number, so both documents name the same build.

Check it in CI
--------------

``python-sbom validate`` needs the ``validate`` extra, and says so when it is missing. It checks every CycloneDX SBOM in
each wheel's ``.dist-info/sboms`` against the CycloneDX 1.6 schema. For the SBOM python-sbom wrote, it also requires the
``urn:uuid`` serial number ``actions/attest`` needs to recognize the format, checks that every reference resolves, and
validates the SPDX rendering; an SBOM another tool wrote, such as auditwheel's, gets the schema check alone:

.. code-block:: console

    $ python -m pip install 'python-sbom[validate]'
    $ python-sbom validate dist/ --allow-license MIT --allow-license Apache-2.0

Each ``--allow-license`` adds an SPDX id that bundled wheels may use. With any given, a bundled wheel whose license the
ids do not allow fails the check, and so does one that declares a license only by name.

Before anything else, ``validate`` counts the components an SBOM lists, nested ones included, and fails an SBOM that
lists more than 100,000 without checking it further. Every check takes time in proportion to the count: 100,000 files
take about a second, and 100,000 packages, each also checked in the SPDX rendering, about six. The cap thus bounds what
an untrusted SBOM can ask of a CI job while staying far above real SBOMs: every file of the wheel, of each bundled wheel
and of each build tool counts, and virtualenv's wheel lists about 5,200. Raise the cap for an SBOM you expect to be
larger, or lower it to refuse more:

.. code-block:: console

    $ python-sbom validate dist/ --max-components 500000

The cap also sets the size limit: 1 KiB per component plus 1 MiB, 103,448,576 bytes at the default, about twice the 54
MB python-sbom writes for 100,000 components. ``validate`` refuses a larger SBOM before parsing it, and reads the SBOMs
of a wheel one at a time, so memory holds only one however many the wheel packs. It also refuses an SBOM nested more
than 128 levels deep; the SBOMs python-sbom and other tools write nest about a dozen levels.
