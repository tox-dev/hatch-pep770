Python API
==========

The core is importable from ``python_sbom`` without hatchling; the hatchling build hook lives in ``python_sbom.hatch``.
:doc:`explanation` shows how the pieces fit together.

.. py:data:: python_sbom.__version__
    :type: str

    The installed version of python-sbom.

Hatchling build hook
--------------------

.. autoclass:: python_sbom.hatch.SbomBuildHook
    :members: content_provider, backend

Pipeline
--------

.. autofunction:: python_sbom.build_sbom

.. autoclass:: python_sbom.Sbom
    :members: content

.. autoclass:: python_sbom.Backend
    :members: request

.. autoclass:: python_sbom.MetadataBackend

.. autoclass:: python_sbom.BuiltWheel

.. autoclass:: python_sbom.ContentProvider
    :members: bundled_wheel, contributions

.. autofunction:: python_sbom.load_content_provider

.. autofunction:: python_sbom.embed_sbom

Collecting inputs
-----------------

.. autofunction:: python_sbom.settings_from_pyproject

.. autofunction:: python_sbom.settings_from_table

.. py:data:: python_sbom.Toml

    A value of a TOML table, as :mod:`tomllib` or hatchling hand it over: a string, number, boolean, date or time, or
    an array or table of them.

.. autofunction:: python_sbom.collect_facts

.. autoclass:: python_sbom.RevisionReader
    :special-members: __call__

.. autofunction:: python_sbom.default_revision

.. autofunction:: python_sbom.git_revision

.. autofunction:: python_sbom.read_source_tree

.. autofunction:: python_sbom.read_bundled_wheel

Inputs
------

.. autoclass:: python_sbom.SbomRequest

.. autoclass:: python_sbom.Settings

.. autoclass:: python_sbom.BuildFacts

.. autoclass:: python_sbom.Interpreter

.. autoclass:: python_sbom.InstalledDistribution

.. autoclass:: python_sbom.Revision

.. autoclass:: python_sbom.RecordRow

.. autoclass:: python_sbom.SourceTree

.. autoclass:: python_sbom.BundledWheel

.. autoclass:: python_sbom.BuildScript

.. autoclass:: python_sbom.BundledWheelInfo

.. autoclass:: python_sbom.Contributions

Building blocks
---------------

.. autofunction:: python_sbom.component_from_metadata

.. autofunction:: python_sbom.bundled_wheel_component

.. autofunction:: python_sbom.file_component_from_bytes

.. autofunction:: python_sbom.script_tool

.. autofunction:: python_sbom.tool_components

.. autofunction:: python_sbom.formulation

.. autofunction:: python_sbom.project_identity

.. autoclass:: python_sbom.ProjectIdentity

.. autofunction:: python_sbom.document

.. autofunction:: python_sbom.dumps

SPDX and validation
-------------------

.. autofunction:: python_sbom.to_spdx

.. autofunction:: python_sbom.validate

.. autofunction:: python_sbom.validate_wheel

Errors
------

.. autoexception:: python_sbom.SbomError

.. autoexception:: python_sbom.SettingsError

.. autoexception:: python_sbom.WheelError

.. autoexception:: python_sbom.SourceRevisionError

.. autoexception:: python_sbom.MissingExtraError

Types
-----

These are :class:`~typing.TypedDict` types of the JSON documents, for type checking code that builds or reads them. Each
follows the CycloneDX 1.6 JSON object of the same name; the `CycloneDX 1.6 reference
<https://cyclonedx.org/docs/1.6/json/>`_ describes every key.

.. py:class:: python_sbom.Document

    A complete CycloneDX 1.6 document: the ``$schema``, ``bomFormat``, ``specVersion``, ``serialNumber`` and ``version``
    header, plus the keys of :class:`~python_sbom.Body`. See the `BOM <https://cyclonedx.org/docs/1.6/json/>`_
    reference.

.. autoclass:: python_sbom.Body
    :no-members:

.. py:class:: python_sbom.Component

    A distribution, application, platform or file, with ``type``, ``bom-ref`` and ``name`` and the optional
    ``version``, ``purl``, ``supplier``, ``authors``, ``description``, ``licenses``, ``copyright``, ``hashes``,
    ``externalReferences``, ``properties``, ``evidence`` and nested ``components``. See the `component
    <https://cyclonedx.org/docs/1.6/json/#components>`_ reference.

.. autoclass:: python_sbom.Dependency
    :no-members:

.. py:class:: python_sbom.Formula

    How an artifact was built: a ``bom-ref`` and one or more ``workflows``, each with the tools it used as
    ``resourceReferences``, its ``outputs`` and, optionally, its ``inputs``. See the `formulation
    <https://cyclonedx.org/docs/1.6/json/#formulation>`_ reference.

.. autoclass:: python_sbom.License
    :no-members:

.. autoclass:: python_sbom.OrganizationalEntity
    :no-members:

.. autoclass:: python_sbom.Property
    :no-members:

.. autoclass:: python_sbom.Spdx
    :no-members:

Command line
------------

.. autofunction:: python_sbom.main
