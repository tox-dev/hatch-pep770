########################
 Use it with setuptools
########################

python-sbom ships a `setuptools <https://setuptools.pypa.io/>`_ plugin, registered in setuptools'
``setuptools.finalize_distribution_options`` entry point group, the one setuptools-scm uses. Add python-sbom to the
build requirements, with the ``setuptools`` extra, and add a ``[tool.python-sbom]`` table, empty or not:

.. code-block:: toml

    [build-system]
    build-backend = 'setuptools.build_meta'
    requires = ['setuptools>=77', 'python-sbom[setuptools]>=0.2']

    [tool.python-sbom]
    supplier = { name = 'tox-dev', url = ['https://github.com/tox-dev'] }

Every wheel you build now carries the SBOM, and every sdist the source revision. An editable wheel carries none.

setuptools calls the plugin for every build in an environment where python-sbom is installed, so the table is what turns
it on: a project without ``[tool.python-sbom]``, or without a ``pyproject.toml``, builds as before.

The plugin wraps the ``bdist_wheel`` and ``sdist`` commands the project uses, including subclasses it passes to
``setup()`` as ``cmdclass``, and writes the SBOM once the wheel is written.

*********************************************
 Pitfall: commands set in ``pyproject.toml``
*********************************************

setuptools applies ``[tool.setuptools.cmdclass]`` after the plugin runs, so a ``bdist_wheel`` or ``sdist`` named there
would replace the plugin's and the wheel would get no SBOM. The plugin stops such a build with an error instead. Move
that command to ``setup.py``'s ``cmdclass``, or wrap the backend instead, as :doc:`/how-to/other-backends` shows with
``build-backend = 'setuptools.build_meta'``.

***************************************
 Pitfall: build output in the checkout
***************************************

setuptools writes ``build/`` and ``<name>.egg-info/`` into the project directory, and frontends run ``egg_info`` before
they ask for the wheel or sdist. python-sbom counts untracked files as changes, so unless git ignores both, every build
reads the checkout as modified: the wheel's SBOM names no exact commit, and the sdist carries no source revision. Ignore
them:

.. code-block:: text

    build/
    dist/
    *.egg-info/
