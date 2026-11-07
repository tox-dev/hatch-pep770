Use it
======

With hatchling
--------------

Add the hook to ``build-system.requires`` and enable it with an empty table, as the quick start on the :doc:`index`
shows. hatchling 1.28 added SBOM support to wheels, so the hook requires it. The hook acts on wheel builds only; an
sdist carries no SBOM.

The SBOM links to the wheel's PyPI attestation, so it needs the wheel's tag. List the hook after any hook that changes
the tag.

Options
~~~~~~~

Each option lives in the hook's table and is optional.

``supplier``
    The organization that supplies the project: a table with a ``name`` string and an optional ``url`` string array. It
    becomes the supplier and manufacturer of the document and the supplier of the project. Left out, the document names
    no supplier.

    .. code-block:: toml

        [tool.hatch.build.hooks.pep770]
        supplier = { name = 'Python Packaging Authority', url = ['https://www.pypa.io'] }

``repository``
    The repository URL, used for the link to the source revision, the license file and, on GitHub, the security policy
    and advisories. It defaults to the first ``Source``, ``Repository`` or ``GitHub`` URL in ``[project.urls]``.

    .. code-block:: toml

        [tool.hatch.build.hooks.pep770]
        repository = 'https://gitlab.com/example/project'

``default-branch``
    The branch in links to files of the repository, ``main`` by default.

    .. code-block:: toml

        [tool.hatch.build.hooks.pep770]
        default-branch = 'trunk'

``bundled-wheels``
    Glob patterns, relative to the project root, of wheels the project ships as data files. Each matching wheel becomes
    a component with its SHA-256, license, files and the packages it vendors.

    .. code-block:: toml

        [tool.hatch.build.hooks.pep770]
        bundled-wheels = ['src/project/wheels/*.whl']

A bundled wheel whose project URLs point to the same forge account as ``repository`` gets the same ``supplier``. Its
vendored packages come from ``_vendor/vendor.txt``, pip's manifest, whose lines must each pin one exact version, and
from any ``.dist-info/METADATA`` under ``_vendor/``.

With another build backend
--------------------------

A backend other than hatchling, such as `meson-python <https://mesonpy.readthedocs.io/>`_, cannot run the hook.
``hatch-pep770 embed`` writes the same document into a wheel that backend built, adds the ``RECORD`` row, and keeps
every other entry of the archive as it was. It reads the options above from a ``[tool.hatch-pep770]`` table:

.. code-block:: toml

    [tool.hatch-pep770]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Build, then embed, from the project root:

.. code-block:: console

    $ python -m build --wheel
    $ hatch-pep770 embed dist/*.whl
    wrote turbohtml-1.0.dist-info/sboms/turbohtml.cdx.json into turbohtml-1.0-cp314-cp314-linux_x86_64.whl

The build tool record describes the environment ``embed`` runs in, not the isolated environment the backend built in.
To record the build toolchain, build without isolation in the same locked environment:

.. code-block:: console

    $ python -m pip install hatch-pep770 meson-python meson ninja
    $ python -m build --wheel --no-isolation
    $ hatch-pep770 embed dist/*.whl

Render it as SPDX
-----------------

Some tools read only `SPDX <https://spdx.dev/>`_. ``hatch-pep770 spdx`` renders the CycloneDX document as SPDX 2.3
JSON:

.. code-block:: console

    $ unzip -p dist/project-1.0-py3-none-any.whl '*/sboms/project.cdx.json' > project.cdx.json
    $ hatch-pep770 spdx project.cdx.json project.spdx.json

The SPDX document keeps the packages, their hashes, licenses and purls, and the containment, dependency and build tool
relationships. It leaves out the per-file hashes, because SPDX 2.3 wants a SHA-1 for every file and wheel ``RECORD``
files hold SHA-256, and the build record, which SPDX 2.3 has no field for. Its namespace ends in the CycloneDX serial
number, so both documents name the same build.

Check it in CI
--------------

``hatch-pep770 validate`` needs the ``validate`` extra. It checks each wheel's SBOM against the CycloneDX 1.6 schema,
requires the ``urn:uuid`` serial number ``actions/attest`` needs to recognize the format, checks that every reference
resolves, and validates the SPDX rendering:

.. code-block:: console

    $ python -m pip install 'hatch-pep770[validate]'
    $ hatch-pep770 validate dist/ --allow-license MIT --allow-license Apache-2.0

Each ``--allow-license`` adds an SPDX id that bundled wheels may use. With any given, a bundled wheel whose license the
ids do not allow fails the check, and so does one that declares a license only by name.
