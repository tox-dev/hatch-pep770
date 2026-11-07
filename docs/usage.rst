Use it
======

With hatchling
--------------

Add the hook to ``build-system.requires`` and enable it with an empty table, as the quick start on the :doc:`index`
shows. The ``hatch`` extra brings hatchling; the command line and the library need none. The hook acts on wheel builds
only: an sdist and an editable wheel carry no SBOM.

The hook writes the SBOM once hatchling has written the wheel, so the document describes the final file name and
metadata, whatever dependencies or tag other hooks changed. Hatchling runs the hooks in the order of their tables; see
its `build hook documentation <https://hatch.pypa.io/latest/config/build/#build-hooks>`_. The order does not matter
for this hook.

Options
~~~~~~~

The options live in a ``[tool.python-sbom]`` table. Each is optional; an unknown key fails the build, so a typo cannot
pass silently. A key in the hook's own table, such as ``[tool.hatch.build.hooks.python-sbom]``, wins over the same key
in ``[tool.python-sbom]``.

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
    the project knows beyond its metadata; :doc:`extend` shows one.

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

The SBOM names the commit the wheel was built from. It takes the first of: the ``PYTHON_SBOM_COMMIT`` environment
variable; git, for a checkout or any directory inside one; and the ``node`` line of an expanded ``.git_archival.txt``,
for a ``git archive``. A checkout with uncommitted changes to tracked files gets a ``<project>:vcs-dirty`` property, and
the link to the revision says so. A wheel built from an sdist, as ``python -m build`` and ``uv build`` do by default,
has no checkout, so set ``PYTHON_SBOM_COMMIT`` or ship ``.git_archival.txt`` to keep the commit.

With another build backend
--------------------------

A backend other than hatchling, such as `meson-python <https://mesonbuild.com/meson-python/>`_, cannot run the hook.
``python-sbom embed`` writes the same document into a wheel that backend built, adds the ``RECORD`` row, and keeps
every other entry of the archive as it was. It reads the options from ``[tool.python-sbom]``:

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

The build tool record lists the environment named by ``--build-env``, by default the one ``embed`` runs in. To record
the real toolchain, point ``--build-env`` at the build environment's ``site-packages``, or build without isolation in
the same locked environment. On Linux, meson-python also needs ``patchelf`` there:

.. code-block:: console

    $ python -m pip install python-sbom meson-python meson ninja patchelf
    $ python -m build --wheel --no-isolation
    $ python-sbom embed dist/*.whl

``auditwheel repair`` renames a Linux wheel to its ``manylinux`` tag, so the attestation link in an SBOM written
before the repair names the old file. Run ``embed`` on the repaired wheel, after ``auditwheel``, to describe the file
you publish; auditwheel's own SBOM in the same directory stays untouched.

Render it as SPDX
-----------------

Some tools read only `SPDX <https://spdx.dev/>`_. ``python-sbom spdx`` renders the CycloneDX document as SPDX 2.3
JSON:

.. code-block:: console

    $ unzip -p dist/project-1.0-py3-none-any.whl '*/sboms/project.cdx.json' > project.cdx.json
    $ python-sbom spdx project.cdx.json project.spdx.json

The SPDX document keeps the packages, their hashes, licenses and purls, and the containment, dependency and build tool
relationships. It leaves out the per-file hashes, because SPDX 2.3 wants a SHA-1 for every file and wheel ``RECORD``
files hold SHA-256, and the build record, which SPDX 2.3 has no field for. Its namespace ends in the CycloneDX serial
number, so both documents name the same build.

Check it in CI
--------------

``python-sbom validate`` needs the ``validate`` extra, and says so when it is missing. It checks every CycloneDX SBOM
in each wheel's ``.dist-info/sboms`` against the CycloneDX 1.6 schema. For the SBOM python-sbom wrote, it also requires
the ``urn:uuid`` serial number ``actions/attest`` needs to recognize the format, checks that every reference resolves,
and validates the SPDX rendering; an SBOM another tool wrote, such as auditwheel's, gets the schema check alone:

.. code-block:: console

    $ python -m pip install 'python-sbom[validate]'
    $ python-sbom validate dist/ --allow-license MIT --allow-license Apache-2.0

Each ``--allow-license`` adds an SPDX id that bundled wheels may use. With any given, a bundled wheel whose license the
ids do not allow fails the check, and so does one that declares a license only by name.
