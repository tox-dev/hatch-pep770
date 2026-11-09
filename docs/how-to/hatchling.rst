#######################
 Use it with hatchling
#######################

python-sbom ships a hatchling_ :term:`build hook`. Add it to the build requirements, with the ``hatch`` extra, and
enable it with an empty table:

.. code-block:: toml

    [build-system]
    build-backend = 'hatchling.build'
    requires = ['hatchling>=1.28', 'python-sbom[hatch]>=0.2']

    [tool.hatch.build.hooks.python-sbom]

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every :term:`wheel` you build now carries the :term:`SBOM`. An editable wheel carries none, and an :term:`sdist` carries
the :term:`source revision` instead, so a wheel built from it still names its commit.

Put python-sbom's options in ``[tool.python-sbom]``, the table every integration reads, never in the hook's table: the
hook's table holds only hatchling's own options, such as ``enable-by-default``, and a python-sbom option there fails the
build with a pointer to ``[tool.python-sbom]``. :doc:`/reference/configuration` lists the options.

The hook writes the SBOM once hatchling has written the wheel, so the document describes the final file name and
metadata, whatever dependencies or tag other hooks changed. The order of the hook tables does not matter.

**************************************************************
 When a project supports Python versions python-sbom does not
**************************************************************

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
        from hatchling.builders.hooks.plugin.interface import (
            BuildHookInterface as SbomBuildHook,
        )


    def get_build_hook():
        return SbomBuildHook

Wheels built on Python 3.11 or later carry the SBOM; publish those.

********************
 From a custom hook
********************

A project with its own hatchling custom hook can subclass :class:`~python_sbom.hatch.SbomBuildHook` instead of enabling
the plugin, and override :meth:`~python_sbom.hatch.SbomBuildHook.content_provider` to hand python-sbom what the hook
knows. :doc:`/how-to/content-provider` walks through one.

*****************************************
 Release builds that install from a lock
*****************************************

A release workflow that installs ``[build-system] requires`` from a lock with hashes, such as `tox-dev/github-workflows
<https://github.com/tox-dev/github-workflows>`_ does, needs python-sbom and its dependencies (``installer``,
``packageurl-python``, ``packaging`` and ``zipremove``) in the locked group, or the build stops on a missing hash.
