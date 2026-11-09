###############
 How-to guides
###############
Each guide solves one task and assumes you know what python-sbom does, as the :doc:`tutorials` show. The first four set it up for a build backend; the rest describe other artifacts, add what a project knows, and check the result. The :doc:`reference` lists every option and command, and :doc:`concepts` explains the design.

***********************
 Use it with hatchling
***********************

python-sbom ships a `hatchling <https://hatch.pypa.io/latest/>`_ build hook. Add it to the build requirements, with the
``hatch`` extra, and enable it with an empty table:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatchling>=1.28', 'python-sbom[hatch]>=0.2']

    [tool.hatch.build.hooks.python-sbom]

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every wheel you build now carries the SBOM. An editable wheel carries none, and an sdist carries the source revision
instead, so a wheel built from it still names its commit.

Put python-sbom's options in ``[tool.python-sbom]``, the table every integration reads, never in the hook's table:
the hook's table holds only hatchling's own options, such as ``enable-by-default``, and a python-sbom option there fails
the build with a pointer to ``[tool.python-sbom]``. :ref:`reference:Configuration` lists the options.

The hook writes the SBOM once hatchling has written the wheel, so the document describes the final file name and
metadata, whatever dependencies or tag other hooks changed. The order of the hook tables does not matter.

When a project supports Python versions python-sbom does not
============================================================

python-sbom needs Python 3.11 or later. A project that still builds on older interpreters guards the requirement with a
marker. An enabled ``python-sbom`` hook table would then fail those builds, since hatchling refuses a hook it cannot
find, so enable the hook from a custom hook script that falls back to a hook doing nothing:

.. code-block:: text

    [build-system]
    requires = ['hatchling>=1.28', '''python-sbom[hatch]>=0.2; python_version>='3.11'''']

    [tool.hatch.build.hooks.custom]
    path = 'hatch_build.py'

.. code-block:: python

    # hatch_build.py
    import sys

    if sys.version_info >= (3, 11):
        from python_sbom.hatch import SbomBuildHook
    else:  # no python-sbom here, so these builds carry no SBOM
        from hatchling.builders.hooks.plugin.interface import BuildHookInterface as SbomBuildHook


    def get_build_hook():
        return SbomBuildHook

Wheels built on Python 3.11 or later carry the SBOM; publish those.

From a custom hook
==================

A project with its own hatchling custom hook can subclass :class:`~python_sbom.hatch.SbomBuildHook` instead of enabling
the plugin, and override :meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to hand python-sbom what the hook
knows. :ref:`how-to:Add what your project knows` walks through one.

Release builds that install from a lock
=======================================

A release workflow that installs ``[build-system] requires`` from a lock with hashes, such as `tox-dev/github-workflows
<https://github.com/tox-dev/github-workflows>`_ does, needs python-sbom and its dependencies (``installer``,
``packageurl-python``, ``packaging`` and ``zipremove``) in the locked group, or the build stops on a missing hash.

*************************
 Use it with pdm-backend
*************************

python-sbom ships a `pdm-backend <https://backend.pdm-project.org/>`_ build hook, registered in pdm-backend's
``pdm.build.hook`` entry point group. Add python-sbom to the build requirements, with the ``pdm`` extra, and add a
``[tool.python-sbom]`` table, empty or not:

.. code-block:: toml

    [build-system]
    build-backend = 'pdm.backend'
    requires = ['pdm-backend>=2.4', 'python-sbom[pdm]>=0.2']

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every wheel you build now carries the SBOM, and every sdist the source revision. An editable wheel carries none.

pdm-backend loads every hook installed in the build environment, so the table is what turns this one on: a project
without ``[tool.python-sbom]`` builds as before even when python-sbom is installed.

The hook runs in pdm-backend's ``pdm_build_finalize`` step, once the wheel is written, so the document describes the
final file name and metadata. When ``SOURCE_DATE_EPOCH`` is unset, pdm-backend dates every wheel entry 2016-01-01, and
the SBOM takes the same time, so a rebuild reproduces both.

A project with its own ``pdm_build.py`` keeps it; both hooks run.

************************
 Use it with setuptools
************************

python-sbom ships a `setuptools <https://setuptools.pypa.io/>`_ plugin, registered in setuptools'
``setuptools.finalize_distribution_options`` entry point group, the one setuptools-scm uses. Add python-sbom to the
build requirements, with the ``setuptools`` extra, and add a ``[tool.python-sbom]`` table, empty or not:

.. code-block:: toml

    [build-system]
    build-backend = 'setuptools.build_meta'
    requires = ['setuptools>=77', 'python-sbom[setuptools]>=0.2']

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every wheel you build now carries the SBOM, and every sdist the source revision. An editable wheel carries none.

setuptools calls the plugin for every build in an environment where python-sbom is installed, so the table is what turns
it on: a project without ``[tool.python-sbom]``, or without a ``pyproject.toml``, builds as before.

The plugin wraps the ``bdist_wheel`` and ``sdist`` commands the project uses, including subclasses it passes to
``setup()`` as ``cmdclass``, and writes the SBOM once the wheel is written.

Pitfall: commands set in ``pyproject.toml``
===========================================

setuptools applies ``[tool.setuptools.cmdclass]`` after the plugin runs, so a ``bdist_wheel`` or ``sdist`` named there
would replace the plugin's and the wheel would get no SBOM. The plugin stops such a build with an error instead. Move
that command to ``setup.py``'s ``cmdclass``, or wrap the backend instead, as :ref:`how-to:Use it with any other backend` shows with
``build-backend = 'setuptools.build_meta'``.

Pitfall: build output in the checkout
=====================================

setuptools writes ``build/`` and ``<name>.egg-info/`` into the project directory, and frontends run ``egg_info`` before
they ask for the wheel or sdist. python-sbom counts untracked files as changes, so unless git ignores both, every build
reads the checkout as modified: the wheel's SBOM names no exact commit, and the sdist carries no source revision. Ignore
them:

.. code-block:: text

    build/
    dist/
    *.egg-info/

*******************************
 Use it with any other backend
*******************************

Backends without a plugin interface, such as meson-python, maturin, scikit-build-core, flit-core, poetry-core and
uv_build, get the SBOM through ``python_sbom.backend``, a build backend that wraps yours. Make it the project's backend,
keep yours in the build requirements, and name yours in ``[tool.python-sbom]``:

.. code-block:: toml

    [build-system]
    build-backend = 'python_sbom.backend'
    requires = ['meson-python>=0.18', 'meson>=1.6', 'ninja', 'python-sbom>=0.2']

    [tool.python-sbom]
    build-backend = 'mesonpy'
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

``build-backend`` takes what ``[build-system] build-backend`` took before: a module, or ``module:object``. Every hook a
frontend calls goes to your backend unchanged, ``--config-settings`` included, and the optional hooks exist only when
your backend defines them, so frontends behave as before. Once your backend has written a wheel, the wrapper writes the
SBOM into it; once it has written an sdist, it adds the source revision.

The wrapper runs inside the build's isolated environment, so the SBOM lists the tools that built the wheel, such as
meson-python, meson, ninja and patchelf, with the versions the frontend installed.

Each backend
============

Use the module name from your current ``[build-system] build-backend``:

.. list-table::
    :header-rows: 1

    * - Backend
      - ``[tool.python-sbom] build-backend``
      - Notes
    * - `meson-python <https://meson-python.readthedocs.io/>`_
      - ``mesonpy``
      - Its sdist step needs a git or Mercurial checkout, as without the wrapper.
    * - `maturin <https://www.maturin.rs/>`_
      - ``maturin``
      - maturin writes its own SBOM of the Rust crates next to python-sbom's; see below.
    * - `scikit-build-core <https://scikit-build-core.readthedocs.io/>`_
      - ``scikit_build_core.build``
      - A project built with hatchling and scikit-build-core's hatch plugin uses :ref:`how-to:Use it with hatchling` instead.
    * - `flit-core <https://flit.pypa.io/>`_
      - ``flit_core.buildapi``
      -
    * - `poetry-core <https://python-poetry.org/docs/pyproject/>`_
      - ``poetry.core.masonry.api``
      -
    * - `uv_build <https://docs.astral.sh/uv/concepts/build-backend/>`_
      - ``uv_build``
      - ``uv build`` builds a uv_build project in its own process, skipping the build interface; with the wrapper as the
        backend, it calls the build interface, so the wrapper runs.
    * - pdm-backend, setuptools
      - ``pdm.backend``, ``setuptools.build_meta``
      - Use :ref:`how-to:Use it with pdm-backend` or :ref:`how-to:Use it with setuptools` instead; wrap them only when the plugin cannot act.

maturin's own SBOM
------------------

`maturin writes a CycloneDX SBOM <https://www.maturin.rs/sbom>`_ of the Rust crates a wheel links, as
``<crate>.cyclonedx.json``. PEP 770 allows several SBOMs per wheel, so python-sbom's ``<name>.cdx.json`` sits next to it:
maturin's lists the crates, python-sbom's the wheel's files, metadata, build tools and source revision.

Pitfall: builds that skip the build interface
=============================================

The wrapper runs only when a frontend builds through the standard build interface: pip, uv, ``python -m build`` and
cibuildwheel do. Tools that call the backend's own command line do not: ``maturin build``, which `maturin-action
<https://github.com/PyO3/maturin-action>`_ runs, and ``meson`` called directly. Describe those wheels after the build, as
:ref:`how-to:Describe a wheel built outside the build interface` shows.

Pitfall: a backend in your own tree
===================================

The wrapper cannot wrap a backend the project ships in its own tree. Such a backend loads through ``[build-system]
backend-path``, and a frontend loads only a backend found on that path, so it refuses ``python_sbom.backend``, which
lives in the build environment. Describe those wheels after the build, as :ref:`how-to:Describe a wheel built outside the build interface` shows.

Pitfall: tools that rename the wheel afterwards
===============================================

``auditwheel repair`` and ``delocate`` rename a wheel to its final platform tag and may copy shared libraries into it, so
the SBOM the wrapper wrote names the old file and misses those libraries. Run ``python-sbom embed`` on the repaired
wheel, as :ref:`how-to:Describe a wheel built outside the build interface` shows.

****************************************************
 Describe a wheel built outside the build interface
****************************************************

Some wheels never pass through a python-sbom plugin or the wrapper backend: maturin-action calls ``maturin build``
directly, and ``auditwheel repair`` or ``delocate`` rename a wheel after the build and may copy libraries into it.
``python-sbom embed`` describes such a wheel after the fact. It writes the same document the plugins write, adds its
``RECORD`` row, keeps every other entry of the wheel as it was, and replaces an SBOM python-sbom wrote before.

Embed after the build
=====================

Run it from the project root, so it finds ``[tool.python-sbom]``:

.. code-block:: console

    $ maturin build --release --out dist
    $ python-sbom embed dist/*.whl
    wrote matex-1.0.dist-info/sboms/matex.cdx.json into matex-1.0-py3-none-manylinux_2_17_x86_64.whl

Record the real build tools
===========================

``embed`` lists the packages of the environment ``--build-env`` names, by default the one it runs in, and always the
interpreter it runs on. Unless that is the environment the wheel was built in, the record does not match the real build.
Either build without isolation in the environment ``embed`` runs in, installed from the same lock:

.. code-block:: console

    $ python -m pip install build python-sbom meson-python meson ninja patchelf
    $ python -m build --wheel --no-isolation
    $ python-sbom embed dist/*.whl

or install the build requirements into an environment of their own and point ``--build-env`` at its ``site-packages``:

.. code-block:: console

    $ python -m venv build-env && build-env/bin/pip install maturin
    $ python-sbom embed dist/*.whl --build-env build-env/lib/python3.15/site-packages

After a repair
==============

Run ``embed`` on the repaired wheel, so the SBOM names the file you publish:

.. code-block:: console

    $ auditwheel repair dist/*.whl --wheel-dir wheelhouse
    $ python-sbom embed wheelhouse/*.whl

auditwheel's own SBOM, ``auditwheel.cdx.json``, stays in the wheel next to python-sbom's.

Name the source revision
========================

``embed`` reads the commit from the checkout it runs in. A wheel built from an sdist elsewhere names its commit through
``--commit`` or the ``PYTHON_SBOM_COMMIT`` environment variable; :ref:`reference:Configuration` lists the order in
which python-sbom looks for it.

**************************************
 Describe a zipapp or another archive
**************************************

A project may also publish a zipapp, such as virtualenv's ``virtualenv.pyz``, which holds virtualenv's own
``.dist-info`` at its top level, the wheels it seeds, and its dependencies unpacked under ``__virtualenv__/``.
``python-sbom archive`` describes such an archive the way the hook describes a wheel: the archive's own files, the
project's distribution, each wheel it bundles as a ``.whl`` member, and each one unpacked into a directory with a
``.dist-info``. The content provider the option names hears of every bundled wheel, and its context reads the archive's
files:

.. code-block:: console

    $ python-sbom archive virtualenv.pyz --build-script tasks/make_zipapp.py --embed
    wrote virtualenv.pyz.cdx.json
    wrote virtualenv.pyz.cdx.json into virtualenv.pyz

The document takes its options, source revision and toolchain the way the wheel's does, so both name the project alike.
Its build time comes from ``SOURCE_DATE_EPOCH``, or the current time without it; set ``SOURCE_DATE_EPOCH`` for both
builds to give them one time. ``--embed`` adds the document to the archive's top level, where ``python-sbom validate
virtualenv.pyz`` finds it. It goes in deflated at level 9 whatever the archive's other members use, since a zipapp may
store them all and the SBOM, megabytes of JSON, would then add its full size. The entry carries a fixed time and Unix
attributes and the other members keep their bytes, so adding it to one archive gives the same bytes on every system with
the same zlib.

*****************************
 Add what your project knows
*****************************

The options cover what every project shares. A project that knows more than its metadata says adds it through a content
provider, and the same provider serves the wheel's SBOM and the SBOM of any other archive the project publishes, through
every integration.

Write a provider
================

A :class:`~python_sbom.ContentProvider` has two methods. Each receives a :class:`~python_sbom.ProviderContext`: the
project directory, its :class:`~python_sbom.Settings`, its :class:`~python_sbom.ProjectIdentity` with the prefix of its
properties, and :meth:`~python_sbom.ProviderContext.read`, which reads a file of the artifact being described, a member
of the built wheel or of the archive. Each returns a value whose fields default to empty, so a provider names only what
it adds.

- :meth:`~python_sbom.ContentProvider.bundled_wheel` returns the properties and the supplier of one bundled wheel. The
  properties follow ``<prefix>:bundled-wheel`` and come before those from the wheel's metadata. A wheel's supplier comes
  only from here, never from the wheel's own metadata.
- :meth:`~python_sbom.ContentProvider.contributions` returns extra top-level components, the dependencies between them,
  root properties and build tools, such as the C libraries a native wheel links. They join the document before the
  root's dependencies and the serial number derive from it. The build fails when a component or tool lacks ``type``,
  ``bom-ref`` or ``name``, a ``bom-ref`` repeats, the ``formula:`` and ``workflow:`` refs of the build's formulation
  included, a dependency names one that no component has, a ``bom-ref`` gets a second dependency entry (the root's
  included, which python-sbom writes), or a root property uses the project's own prefix.

Name the provider in the ``content-provider`` option, as ``module:attribute`` importable from the project root, and every
plugin, the wrapper backend, ``python-sbom embed`` and ``python-sbom archive`` load it. When the provider's class lives in the project, the
SBOM lists its module among the build tools, hashed, because it shapes the document a rebuild has to reproduce:

.. code-block:: python

    from python_sbom import ContentProvider, Contributions


    class Content(ContentProvider):
        def contributions(self, context):
            zlib = {'type': 'library', 'bom-ref': 'pkg:generic/zlib@1.3.1', 'name': 'zlib', 'version': '1.3.1'}
            return Contributions(components=[zlib])

The context has no method that lists files. A provider that needs the wheel's file list reads its ``RECORD`` through
:meth:`~python_sbom.ProviderContext.read`, by the path of the project's ``.dist-info`` directory, such as
``seeder-1.0.dist-info/RECORD``; an archive holds that directory at its top level, and the path reads the same there. The
provider knows the project's name, and a hook subclass, shown below, can hand it hatchling's ``self.metadata.version``.
Any other member reads the same way, by its path inside the artifact.

Worked example: a seeder
========================

A seeder, a project like `virtualenv <https://virtualenv.pypa.io/en/latest/>`_, ships the wheels it installs into new
environments under ``src/seeder/embed``. A ``BUNDLE_SUPPORT`` table in that package's ``__init__.py``, after a
``BUNDLE_FOLDER`` assignment, decides which Python versions receive each wheel. The project's options name the supplier
and the wheels, and enable hatchling's custom hook, which loads ``hatch_build.py`` from the project root:

.. literalinclude:: ../tests/_seeder/pyproject.toml
    :language: toml
    :start-at: [tool.hatch]

The hook script subclasses :class:`~python_sbom.hatch.SbomBuildHook` and overrides
:meth:`~python_sbom.hatch.SbomBuildHook.content_provider`, so it builds the provider with the table's name, an argument
the ``content-provider`` option has no way to pass. ``get_build_hook`` tells hatchling which class to load, since the
script also imports the base class. The provider reads the table next to each wheel through the context, by name,
without importing the package, and names the project's supplier as the wheels' supplier, since the seeder bundles only
that supplier's wheels. The test suite builds this project:

.. literalinclude:: ../tests/_seeder/hatch_build.py
    :language: python

The SBOM lists ``hatch_build.py`` among the build tools, hashed. The bundled pip wheel's component then carries these
properties first, in this order, followed by those from its own metadata:

.. list-table::
    :header-rows: 1

    * - Property
      - Value
    * - ``seeder:bundled-wheel``
      - ``seeder/embed/pip-1.0-py3-none-any.whl``
    * - ``seeder:seeded-for-python``
      - ``3.14``
    * - ``seeder:seeded-for-python``
      - ``3.15``

A bundled wheel is named by its path inside the artifact, so the wheel's SBOM and an archive's give it the same
``bom-ref``.

A hook subclass serves only the hatchling build: the other integrations, ``python-sbom embed`` and ``python-sbom
archive`` load the provider the ``content-provider`` option or ``--content-provider`` names, and build a class without
arguments. A project that
wants the same provider in every SBOM it publishes gives the provider a constructor without arguments, or a module-level
instance, and names it in the option instead of overriding the hook.

************************
 Render an SBOM as SPDX
************************

Some tools read only `SPDX <https://spdx.dev/>`_. ``python-sbom spdx`` renders the CycloneDX document as SPDX 2.3 JSON.
It needs no extra:

.. code-block:: console

    $ unzip -p dist/project-1.0-py3-none-any.whl '*/sboms/project.cdx.json' > project.cdx.json
    $ python-sbom spdx project.cdx.json project.spdx.json

The SPDX document keeps the packages, their hashes, licenses and purls, and the containment, dependency and build tool
relationships. Its namespace ends in the CycloneDX serial number, so both documents name the same build.

It leaves out two things SPDX 2.3 cannot hold: the per-file hashes, because SPDX 2.3 wants a SHA-1 for every file and
wheel ``RECORD`` files hold SHA-256, and the build record. Keep the CycloneDX document when you need those.

The command checks only the fields the rendering reads. To check the whole document, run ``python-sbom validate``, which
also validates the SPDX rendering; see :ref:`how-to:Check SBOMs in CI`.

*******************
 Check SBOMs in CI
*******************

``python-sbom validate`` checks every CycloneDX SBOM in each wheel's ``.dist-info/sboms`` and in each archive it is
given. Install it with the ``validate`` extra, in a tool environment of its own; it says so when the extra is missing:

.. code-block:: console

    $ pipx install 'python-sbom[validate]'
    $ python-sbom validate dist/

Run it after the build and before the upload, on the files you publish. It fails the job when a wheel has no SBOM, so it
also catches a build that lost the plugin.

What it checks
==============

Every SBOM gets the CycloneDX 1.6 schema check. For the SBOM python-sbom wrote, it also requires the ``urn:uuid`` serial
number `actions/attest <https://github.com/actions/attest>`_ needs to recognize the format, checks that every reference
resolves, and validates the SPDX rendering. An SBOM another tool wrote, such as auditwheel's or maturin's, gets the
schema check alone.

Limit the licenses of bundled wheels
====================================

Each ``--allow-license`` adds an SPDX id that bundled wheels may use. With any given, a bundled wheel whose license the
ids do not allow fails the check, and so does one that declares a license only by name:

.. code-block:: console

    $ python-sbom validate dist/ --allow-license MIT --allow-license Apache-2.0

Check a large SBOM
==================

``validate`` refuses an SBOM with more than 100,000 components before it checks anything else, which bounds what an
untrusted SBOM can ask of a CI job. Raise the cap for an SBOM you expect to be larger:

.. code-block:: console

    $ python-sbom validate dist/ --max-components 500000

:ref:`reference:Configuration` lists the limits and why they sit where they do.
