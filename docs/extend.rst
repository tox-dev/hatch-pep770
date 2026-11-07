Extend it
=========

The options cover what every project shares. When a project knows more about a bundled wheel than its metadata says,
it subclasses the hook. When it ships an artifact other than a wheel, it builds that artifact's SBOM from the same
pieces the hook uses.

Add properties to bundled wheels
--------------------------------

:class:`~python_sbom.hatch.SbomBuildHook` calls :meth:`~python_sbom.hatch.SbomBuildHook.bundled_wheel_properties` once per
bundled wheel. Override it in a hatchling `custom build hook <https://hatch.pypa.io/latest/plugins/build-hook/custom/>`_
to add properties. They follow ``<project>:bundled-wheel`` and come before those taken from the wheel's metadata. The
options then live in the custom hook's table, and the SBOM lists the script among the build tools, hashed, because the
script shapes the document a rebuild has to reproduce.

Worked example: virtualenv
~~~~~~~~~~~~~~~~~~~~~~~~~~

`virtualenv <https://virtualenv.pypa.io/>`_ ships the pip and setuptools wheels it installs into new environments,
under ``src/virtualenv/seed/wheels/embed``. A ``BUNDLE_SUPPORT`` table in that package's ``__init__.py`` decides which
Python versions receive each wheel. Its ``pyproject.toml`` names the supplier and the wheels:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatch-vcs>=0.5', 'hatchling>=1.28', 'python-sbom[hatch]>=0.1']

    [tool.hatch.build.hooks.custom]
    path = 'hatch_build.py'
    supplier = { name = 'Python Packaging Authority', url = ['https://www.pypa.io'] }
    bundled-wheels = ['src/virtualenv/seed/wheels/embed/*.whl']

``hatch_build.py`` turns the table into a ``virtualenv:seeded-for-python`` property per Python version:

.. code-block:: python

    from __future__ import annotations

    import ast
    from pathlib import Path
    from typing import TYPE_CHECKING

    from python_sbom.hatch import SbomBuildHook

    if TYPE_CHECKING:
        from python_sbom import Property


    class VirtualenvSbomHook(SbomBuildHook):
        def bundled_wheel_properties(self, wheel: Path) -> list[Property]:
            embed = Path(self.root) / 'src' / 'virtualenv' / 'seed' / 'wheels' / 'embed' / '__init__.py'
            tree = ast.parse(embed.read_text(encoding='utf-8'))
            support: dict[str, dict[str, str]] = ast.literal_eval(
                next(node.value for node in tree.body if isinstance(node, ast.Assign))
            )
            return [
                {'name': 'virtualenv:seeded-for-python', 'value': python}
                for python, wheels in support.items()
                if wheel.name in wheels.values()
            ]


    def get_build_hook() -> type[VirtualenvSbomHook]:
        return VirtualenvSbomHook

The ``get_build_hook`` function tells hatchling which class to load, since the module also sees the base class it
imports. The pip component of the wheel's SBOM then carries these properties, in this order:

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
environment marker on the requirement, ``python-sbom[hatch]>=0.1; python_version >= '3.11'``. Its script then falls back to
hatchling's plain hook there, so those builds produce a wheel without an SBOM:

.. code-block:: python

    import sys

    if sys.version_info >= (3, 11):
        from python_sbom.hatch import SbomBuildHook as BaseHook
    else:  # python-sbom needs Python 3.11; older builds get no SBOM
        from hatchling.builders.hooks.plugin.interface import BuildHookInterface as BaseHook

Describe another artifact
-------------------------

virtualenv also publishes a zipapp. Its SBOM describes what the archive holds and records the same build toolchain as
the wheel's. The pieces the hook uses are public for that:

- :class:`~python_sbom.BuildFacts` collects the build time from ``SOURCE_DATE_EPOCH``, the source revision and the
  interpreter and distributions of the running environment, once, at the edge.
- :func:`~python_sbom.component_from_metadata` turns a distribution's ``METADATA`` into a component, with licenses,
  project URLs and metadata properties.
- :func:`~python_sbom.document` adds the CycloneDX header, with a serial number derived from the content.

This function, which the test suite runs and validates, describes a zipapp with no components yet:

.. literalinclude:: examples/zipapp.py
    :language: python
    :pyobject: describe_zipapp

:func:`~python_sbom.validate` checks the result the way ``python-sbom validate`` checks a wheel's SBOM.

Add another build backend
-------------------------

A build system other than hatchling plugs in by subclassing :class:`~python_sbom.Backend`. The subclass supplies the
wheel's metadata, its file name, the project directory and the settings; :meth:`~python_sbom.Backend.sbom` does the
rest. :class:`~python_sbom.BuiltWheel`, the backend behind ``python-sbom embed``, reads all of that from a finished
wheel; subclass it and override :meth:`~python_sbom.Backend.bundled_wheel_properties` to add properties to bundled wheels
without hatchling.
