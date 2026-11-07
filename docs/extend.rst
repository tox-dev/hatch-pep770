Extend it
=========

The options cover what every project shares. A project that knows more than its metadata says adds it through a content
provider, and the same provider serves the wheel's SBOM and the SBOM of any other archive the project publishes.

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
- :meth:`~python_sbom.ContentProvider.contributions` returns extra top-level components, the dependencies between them,
  root properties and build tools, such as the C libraries a native wheel links. They join the document before the
  root's dependencies and the serial number derive from it. The build fails when a component or tool lacks ``type``,
  ``bom-ref`` or ``name``, a ``bom-ref`` repeats, the ``formula:`` and ``workflow:`` refs of the build's formulation
  included, a dependency names one that no component has, a ``bom-ref`` gets a second dependency entry (the root's
  included, which python-sbom writes), or a root property uses the project's own prefix.

Name the provider in the ``content-provider`` option, as ``module:attribute`` importable from the project root, and the
hook, ``python-sbom embed`` and ``python-sbom archive`` all load it. When the provider's class lives in the project, the
SBOM lists its module among the build tools, hashed, because it shapes the document a rebuild has to reproduce:

.. code-block:: python

    from python_sbom import ContentProvider, Contributions


    class Content(ContentProvider):
        def contributions(self, context):
            zlib = {'type': 'library', 'bom-ref': 'pkg:generic/zlib@1.3.1', 'name': 'zlib', 'version': '1.3.1'}
            return Contributions(components=[zlib])

Worked example: a seeder
------------------------

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

A hook subclass serves only the hatchling build: ``python-sbom embed`` and ``python-sbom archive`` load the provider the
``content-provider`` option or their ``--content-provider`` names, and build a class without arguments. A project that
wants the same provider in every SBOM it publishes gives the provider a constructor without arguments, or a module-level
instance, and names it in the option instead of overriding the hook.

Describe another archive
------------------------

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
virtualenv.pyz`` finds it. It goes in compressed the way most of the archive's members are: by their compression method
and, for deflate, at the level their option bits name, which Python's zipfile leaves at zlib's default. The entry
carries a fixed time and Unix attributes, so adding it to one archive gives the same bytes on every system with the same
zlib.
