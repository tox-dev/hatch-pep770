Extend it
=========

The options cover what every project shares. A project that knows more than its metadata says adds it through a
content provider. A build system other than hatchling plugs in as a backend. An artifact other than a wheel gets its
SBOM from the same public pieces the hook uses.

Add content with a provider
---------------------------

A :class:`~python_sbom.ContentProvider` has two methods, each with a default that adds nothing:

- :meth:`~python_sbom.ContentProvider.bundled_wheel` returns the properties and supplier of one bundled wheel. The
  properties follow ``<project>:bundled-wheel`` and come before those taken from the wheel's metadata.
- :meth:`~python_sbom.ContentProvider.contributions` returns extra top-level components, dependency entries, root
  properties and build tools, such as the C libraries a native wheel links. They join the document before the root's
  dependencies and the serial number are derived from it, so the document stays consistent.

Name the provider in the ``content-provider`` option, and the hook and ``python-sbom embed`` both load it. When it
lives in the project, the SBOM lists its module among the build tools, hashed, because it shapes the document a rebuild
has to reproduce:

.. code-block:: python

    from python_sbom import ContentProvider, Contributions


    class Content(ContentProvider):
        def contributions(self, request):
            zlib = {'type': 'library', 'bom-ref': 'pkg:generic/zlib@1.3.1', 'name': 'zlib', 'version': '1.3.1'}
            return Contributions(components=[zlib], dependencies=[], root_properties=[], tools=[])

Worked example: virtualenv
~~~~~~~~~~~~~~~~~~~~~~~~~~

`virtualenv <https://virtualenv.pypa.io/>`_ ships the pip and setuptools wheels it installs into new environments,
under ``src/virtualenv/seed/wheels/embed``. A ``BUNDLE_SUPPORT`` table in that package's ``__init__.py``, after a
``BUNDLE_FOLDER`` assignment, decides which Python versions receive each wheel. The project already has a hatchling
`custom build hook <https://hatch.pypa.io/latest/plugins/build-hook/custom/>`_, so it subclasses
:class:`~python_sbom.hatch.SbomBuildHook` there, and the options live in the custom hook's table:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatch-vcs>=0.5', 'hatchling>=1.28', 'python-sbom[hatch]>=0.1']

    [tool.hatch.build.hooks.custom]
    path = 'hatch_build.py'
    supplier = { name = 'Python Packaging Authority', url = ['https://www.pypa.io'] }
    bundled-wheels = ['src/virtualenv/seed/wheels/embed/*.whl']

Its ``hatch_build.py`` overrides :meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to hand over a provider that
reads the table next to the wheels by name, without importing the package. The test suite builds a project with
virtualenv's layout from this script:

.. literalinclude:: ../tests/_seeder/hatch_build.py
    :language: python

The ``get_build_hook`` function tells hatchling which class to load, since the module also sees the base class it
imports. The SBOM lists the script among the build tools, hashed. The pip component then carries these properties, in
this order:

.. list-table::
    :header-rows: 1

    * - Property
      - Value
    * - ``virtualenv:bundled-wheel``
      - ``src/virtualenv/seed/wheels/embed/pip-26.1-py3-none-any.whl``
    * - ``virtualenv:seeded-for-python``
      - ``3.14``
    * - ``virtualenv:seeded-for-python``
      - ``3.15``
    * - ``python:requires-python``
      - ``>=3.10``

A project that still builds on a Python older than python-sbom supports, as virtualenv does on 3.9 and 3.10, puts an
environment marker on the requirement, ``python-sbom[hatch]>=0.1; python_version >= '3.11'``. Its script then falls
back to hatchling's plain hook there, so those builds produce a wheel without an SBOM:

.. code-block:: python

    import sys

    if sys.version_info >= (3, 11):
        from python_sbom.hatch import SbomBuildHook as BaseHook
    else:  # python-sbom needs Python 3.11; older builds get no SBOM
        from hatchling.builders.hooks.plugin.interface import BuildHookInterface as BaseHook

Add another build backend
-------------------------

A :class:`~python_sbom.Backend` says what a build system knows about the wheel: :meth:`~python_sbom.Backend.request`
returns the project directory, the core metadata, the wheel's file name, the settings and the build scripts. Two
backends ship:

- :class:`~python_sbom.MetadataBackend` takes the metadata as text, for a build hook of another backend, such as a PDM
  or scikit-build-core plugin, that has it before the wheel exists.
- :class:`~python_sbom.BuiltWheel` reads it from a finished wheel, as ``python-sbom embed`` does.

The pipeline is the same for every backend:

.. code-block:: python

    from python_sbom import (
        ContentProvider,
        MetadataBackend,
        build_sbom,
        collect_facts,
        default_revision,
        read_source_tree,
        settings_from_pyproject,
    )

    settings = settings_from_pyproject(root, {})
    request = MetadataBackend(
        root=root, metadata=core_metadata, wheel_name=wheel_name, settings=settings, build_scripts=()
    ).request()
    facts = collect_facts(root, default_revision, None, None)
    sbom = build_sbom(request, read_source_tree(request), facts, ContentProvider())

``sbom.file_name`` and ``sbom.content`` go into the wheel's ``.dist-info/sboms/``; a backend that can only rewrite a
finished wheel passes them to :func:`~python_sbom.embed_sbom`. In the hatch hook,
:meth:`~python_sbom.hatch.SbomBuildHook.backend` returns the backend, so a subclass can swap it.

Describe another artifact
-------------------------

virtualenv also publishes a zipapp. Its SBOM describes what the archive holds and records the same build toolchain,
time and serial namespace as the wheel's. The pieces are public for that:

- :func:`~python_sbom.collect_facts` reads the build time from ``SOURCE_DATE_EPOCH``, the source revision and the
  interpreter and distributions of the build environment, once, at the edge.
- :func:`~python_sbom.tool_components` turns those facts into build tool components and their dependencies, and
  :func:`~python_sbom.formulation` records the build.
- :func:`~python_sbom.file_component_from_bytes`, :func:`~python_sbom.bundled_wheel_component` and
  :func:`~python_sbom.component_from_metadata` describe what the artifact holds.
- :func:`~python_sbom.project_identity` names the project the way its wheel SBOM does, and :func:`~python_sbom.document`
  adds the CycloneDX header, with a serial number derived from the content.

This function, which the test suite runs and validates, describes a zipapp and the files it holds:

.. literalinclude:: examples/zipapp.py
    :language: python
    :pyobject: describe_zipapp

:func:`~python_sbom.validate` takes the JSON text and needs the ``validate`` extra:
``validate(dumps(document).decode(), None)`` checks the result the way ``python-sbom validate`` checks a wheel's SBOM,
and an allowed license set in place of ``None`` adds the license policy. The ``<project>:sbom:file`` metadata property
marks the document as built from these pieces; without it, the validator treats the document as another tool's and
checks the schema alone.
