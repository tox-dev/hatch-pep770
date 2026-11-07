Extend it
=========

The options cover what every project shares. A project that knows more than its metadata says adds it through a
content provider, and the same provider serves the wheel's SBOM and the SBOM of any other archive the project
publishes.

Add content with a provider
---------------------------

A :class:`~python_sbom.ContentProvider` has two methods. Each receives a :class:`~python_sbom.ProviderContext`: the
project directory, its :class:`~python_sbom.Settings`, its :class:`~python_sbom.ProjectIdentity` with the prefix of its
properties, and :meth:`~python_sbom.ProviderContext.read`, which reads a file of the artifact being described, a member
of the built wheel or of the archive. Each returns a value whose fields default to empty, so a provider names only what
it adds.

- :meth:`~python_sbom.ContentProvider.bundled_wheel` returns the properties and the supplier of one bundled wheel. The
  properties follow ``<prefix>:bundled-wheel`` and come before those from the wheel's metadata. A wheel's supplier comes
  only from here, never from the wheel's own metadata.
- :meth:`~python_sbom.ContentProvider.contributions` returns extra top-level components, the dependencies between
  them, root properties and build tools, such as the C libraries a native wheel links. They join the document before
  the root's dependencies and the serial number derive from it. The build fails when a ``bom-ref`` repeats, a
  dependency names one that no component has, or a root property uses the project's own prefix.

Name the provider in the ``content-provider`` option, as ``module:attribute`` importable from the project root, and
the hook, ``python-sbom embed`` and ``python-sbom archive`` all load it. When the provider's class lives in the
project, the SBOM lists its module among the build tools, hashed, because it shapes the document a rebuild has to
reproduce:

.. code-block:: python

    from python_sbom import ContentProvider, Contributions


    class Content(ContentProvider):
        def contributions(self, context):
            zlib = {'type': 'library', 'bom-ref': 'pkg:generic/zlib@1.3.1', 'name': 'zlib', 'version': '1.3.1'}
            return Contributions(components=[zlib])

Worked example: virtualenv
--------------------------

`virtualenv <https://virtualenv.pypa.io/en/latest/>`_ ships the pip and setuptools wheels it installs into new
environments, under ``src/virtualenv/seed/wheels/embed``. A ``BUNDLE_SUPPORT`` table in that package's ``__init__.py``,
after a ``BUNDLE_FOLDER`` assignment, decides which Python versions receive each wheel. Its options name the supplier
and the wheels:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatch-vcs>=0.5', 'hatchling>=1.28', "python-sbom[hatch]>=0.1; python_version >= '3.11'"]

    [tool.hatch.build.hooks.custom]
    path = 'hatch_build.py'

    [tool.python-sbom]
    supplier = { name = 'Python Packaging Authority', url = ['https://www.pypa.io'] }
    bundled-wheels = ['src/virtualenv/seed/wheels/embed/*.whl']

virtualenv still builds on Python versions python-sbom does not support, so its ``hatch_build.py`` loads the hook
only where the requirement's marker installs it, and hands over a provider that reads the table by name, without
importing the package. The test suite builds a project with virtualenv's layout from this script:

.. literalinclude:: ../tests/_seeder/hatch_build.py
    :language: python

The ``get_build_hook`` function tells hatchling which class to load, since the module also sees the base class it
imports. The SBOM lists the script among the build tools, hashed. The pip component then carries these properties,
in this order:

.. list-table::
    :header-rows: 1

    * - Property
      - Value
    * - ``virtualenv:bundled-wheel``
      - ``virtualenv/seed/wheels/embed/pip-26.1-py3-none-any.whl``
    * - ``virtualenv:seeded-for-python``
      - ``3.14``
    * - ``virtualenv:seeded-for-python``
      - ``3.15``
    * - ``python:requires-python``
      - ``>=3.10``

A bundled wheel is named by its path inside the artifact, so the wheel's SBOM and the zipapp's give it the same
``bom-ref``.

Describe another archive
------------------------

virtualenv also publishes a zipapp, ``virtualenv.pyz``, that holds virtualenv's own ``.dist-info`` at its top level,
the wheels it seeds, and its dependencies unpacked under ``__virtualenv__/``. ``python-sbom archive`` describes such an
archive the way the hook describes a wheel: the archive's own files, the project's distribution, each wheel it
bundles as a ``.whl`` member, and each one unpacked into a directory with a ``.dist-info``. The content provider
hears of every bundled wheel, and its context reads the archive's files:

.. code-block:: console

    $ python-sbom archive virtualenv.pyz --build-script tasks/make_zipapp.py --embed
    wrote virtualenv.pyz.cdx.json
    wrote virtualenv.pyz.cdx.json into virtualenv.pyz

The document takes its options, source revision, build time and toolchain the way the wheel's does, so both name the
project alike. ``--embed`` adds it to the archive's top level, where ``python-sbom validate virtualenv.pyz`` finds it.
