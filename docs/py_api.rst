Python API
==========

The core is importable from ``python_sbom`` without hatchling; the hatchling build hook lives in ``python_sbom.hatch``.

.. autodata:: python_sbom.__version__

Hatchling build hook
--------------------

.. autoclass:: python_sbom.hatch.SbomBuildHook
   :members: bundled_wheel_properties

Backends
--------

.. autoclass:: python_sbom.Backend
   :members:

.. autoclass:: python_sbom.BuiltWheel
   :members: embed

.. autoclass:: python_sbom.ContentProvider
   :members:

Inputs
------

.. autoclass:: python_sbom.Settings
   :members: from_table
   :exclude-members: supplier, repository, default_branch, bundled_wheels

.. autodata:: python_sbom.Toml

.. autoclass:: python_sbom.BuildFacts
   :members: collect, timestamp
   :exclude-members: epoch, commit, tools, tool_dependencies

.. autoclass:: python_sbom.RevisionReader
   :members: __call__

.. autofunction:: python_sbom.git_revision

Building blocks
---------------

.. autofunction:: python_sbom.component_from_metadata

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

Types
-----

These are :class:`~typing.TypedDict` types of the JSON documents, for type checking code that builds or reads them.

.. autoclass:: python_sbom.Document
   :no-members:

.. autoclass:: python_sbom.Body
   :no-members:

.. autoclass:: python_sbom.Component
   :no-members:

.. autoclass:: python_sbom.Dependency
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

.. autoclass:: python_sbom.Options
   :members:
