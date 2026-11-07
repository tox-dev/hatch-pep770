Python API
==========

Everything below is importable from ``python_sbom``.

.. autodata:: python_sbom.__version__

Build hook
----------

.. autoclass:: python_sbom.SbomBuildHook
   :members: bundled_wheel_properties

Wheels from any build backend
-----------------------------

.. autoclass:: python_sbom.Project
   :members: from_table, describe
   :exclude-members: root, supplier, repository, default_branch, bundled_wheels, build_script, bundled_wheel_properties

.. autoclass:: python_sbom.BundledWheelProperties
   :members: __call__

.. autofunction:: python_sbom.embed

Building blocks
---------------

.. autofunction:: python_sbom.component_from_metadata

.. autofunction:: python_sbom.build_tools

.. autofunction:: python_sbom.timestamp

.. autofunction:: python_sbom.document

SPDX and validation
-------------------

.. autofunction:: python_sbom.to_spdx

.. autofunction:: python_sbom.validate

.. autofunction:: python_sbom.validate_wheel

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

.. autodata:: python_sbom.Toml

Command line
------------

.. autofunction:: python_sbom.main

.. autoclass:: python_sbom.Options
   :members:
