Python API
==========

Everything below is importable from ``hatch_pep770``.

.. autodata:: hatch_pep770.__version__

Build hook
----------

.. autoclass:: hatch_pep770.Pep770BuildHook
   :members: bundled_wheel_properties

Wheels from any build backend
-----------------------------

.. autoclass:: hatch_pep770.Project
   :members: from_table, describe
   :exclude-members: root, supplier, repository, default_branch, bundled_wheels, build_script, bundled_wheel_properties

.. autoclass:: hatch_pep770.BundledWheelProperties
   :members: __call__

.. autofunction:: hatch_pep770.embed

Building blocks
---------------

.. autofunction:: hatch_pep770.component_from_metadata

.. autofunction:: hatch_pep770.build_tools

.. autofunction:: hatch_pep770.timestamp

.. autofunction:: hatch_pep770.document

SPDX and validation
-------------------

.. autofunction:: hatch_pep770.to_spdx

.. autofunction:: hatch_pep770.validate

.. autofunction:: hatch_pep770.validate_wheel

Types
-----

These are :class:`~typing.TypedDict` types of the JSON documents, for type checking code that builds or reads them.

.. autoclass:: hatch_pep770.Document
   :no-members:

.. autoclass:: hatch_pep770.Body
   :no-members:

.. autoclass:: hatch_pep770.Component
   :no-members:

.. autoclass:: hatch_pep770.Dependency
   :no-members:

.. autoclass:: hatch_pep770.OrganizationalEntity
   :no-members:

.. autoclass:: hatch_pep770.Property
   :no-members:

.. autoclass:: hatch_pep770.Spdx
   :no-members:

.. autodata:: hatch_pep770.Toml

Command line
------------

.. autofunction:: hatch_pep770.main

.. autoclass:: hatch_pep770.Options
   :members:
