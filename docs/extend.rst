Extend it
=========

The options cover what every project shares. When a project knows more about a bundled wheel than its metadata says,
it subclasses the hook. When it ships an artifact other than a wheel, it builds that artifact's SBOM from the same
pieces the hook uses.

Add properties to bundled wheels
--------------------------------

:class:`~hatch_pep770.Pep770BuildHook` calls :meth:`~hatch_pep770.Pep770BuildHook.bundled_wheel_properties` once per
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
    requires = ['hatch-pep770>=0.1; python_version>='3.11'', 'hatch-vcs>=0.5', 'hatchling>=1.28']

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

    from hatch_pep770 import Pep770BuildHook

    if TYPE_CHECKING:
        from hatch_pep770 import Property


    class SbomBuildHook(Pep770BuildHook):
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


    def get_build_hook() -> type[SbomBuildHook]:
        return SbomBuildHook

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

A project that still builds on a Python older than hatch-pep770 supports keeps the requirement's environment marker
and makes the script fall back to hatchling's plain hook there, so those builds produce a wheel without an SBOM:

.. code-block:: python

    import sys

    if sys.version_info >= (3, 11):
        from hatch_pep770 import Pep770BuildHook as BaseHook
    else:  # hatch-pep770 needs Python 3.11; older builds get no SBOM
        from hatchling.builders.hooks.plugin.interface import BuildHookInterface as BaseHook

Describe another artifact
-------------------------

virtualenv also publishes a zipapp. Its SBOM describes what the archive holds and records the same build toolchain as
the wheel's. The functions the hook uses are public for that:

- :func:`~hatch_pep770.component_from_metadata` turns a distribution's ``METADATA`` into a component, with licenses,
  project URLs and metadata properties.
- :func:`~hatch_pep770.build_tools` records the interpreter and every distribution of the running environment, with
  the files of the pure-Python ones and the dependencies between them.
- :func:`~hatch_pep770.timestamp` gives the time from ``SOURCE_DATE_EPOCH``.
- :func:`~hatch_pep770.document` adds the CycloneDX header, with a serial number derived from the content.

.. code-block:: python

    import uuid

    from hatch_pep770 import Body, Component, build_tools, document, timestamp

    tools, tool_dependencies = build_tools()
    zipapp: Component = {'type': 'application', 'bom-ref': 'pkg:generic/virtualenv.pyz@21.0', 'name': 'virtualenv.pyz'}
    body: Body = {
        'metadata': {
            'timestamp': timestamp(),
            'lifecycles': [{'phase': 'build'}],
            'tools': {'components': tools},
            'component': zipapp,
        },
        'components': [],
        'dependencies': [{'ref': zipapp['bom-ref'], 'dependsOn': []}, *tool_dependencies],
        'formulation': [],
    }
    sbom = document(body, uuid.uuid5(uuid.NAMESPACE_URL, 'https://github.com/pypa/virtualenv/sboms'))

:func:`~hatch_pep770.validate` checks the result the way ``hatch-pep770 validate`` checks a wheel's SBOM.

Use it as a library
-------------------

:class:`~hatch_pep770.Project` holds the options and writes the SBOM of a wheel from its ``METADATA``, and
:func:`~hatch_pep770.embed` rewrites a built wheel with it. Pass ``bundled_wheel_properties`` to add properties to
bundled wheels without a hatchling hook:

.. code-block:: python

    from pathlib import Path

    from hatch_pep770 import Project, embed

    project = Project.from_table(
        {'bundled-wheels': ['src/project/wheels/*.whl']},
        root=Path.cwd(),
        where='my build script',
        bundled_wheel_properties=lambda wheel: [{'name': 'project:role', 'value': 'seed'}],
    )
    embed(Path('dist/project-1.0-py3-none-any.whl'), project)
