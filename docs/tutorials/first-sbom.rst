#################
 Your first SBOM
#################

In this tutorial you build a small package with an :term:`SBOM` inside its :term:`wheel`, look at what the SBOM says,
and check it the way a :term:`CI` job would. It takes about ten minutes. You need Python 3.11 or later, git_, and uv_;
any other :term:`build frontend`, such as ``python -m build``, works the same.

********************
 Create the project
********************

Make a directory with a package, a license and a ``pyproject.toml``. The project uses hatchling_, the backend
python-sbom has the most to say about; :doc:`/reference/backends` lists the others.

.. code-block:: console

    $ mkdir greet && cd greet
    $ mkdir -p src/greet && touch src/greet/__init__.py
    $ printf 'Copyright (c) 2026 You\n\nMIT terms\n' > LICENSE

.. literalinclude:: /examples/hatchling/pyproject.toml
    :language: toml
    :caption: pyproject.toml

The empty ``[tool.hatch.build.hooks.python-sbom]`` table turns the hook on. ``[tool.python-sbom]`` holds python-sbom's
own options; here it names you as the :term:`supplier`. :example:`hatchling` holds the finished project.

Commit it, with the build output ignored, so the SBOM can name the exact :term:`source revision`. A checkout with
uncommitted or untracked files has no commit that reproduces it, and then the SBOM names none:

.. code-block:: console

    $ printf 'dist/\n*.cdx.json\n' > .gitignore
    $ git init --quiet && git add . && git commit --quiet --message first

*****************
 Build the wheel
*****************

.. code-block:: console

    $ uv build
    Successfully built dist/greet-1.0.tar.gz
    Successfully built dist/greet-1.0-py3-none-any.whl

List the wheel's ``.dist-info`` and you find the SBOM next to the metadata:

.. code-block:: console

    $ unzip -Z1 dist/greet-1.0-py3-none-any.whl | grep dist-info
    greet-1.0.dist-info/METADATA
    greet-1.0.dist-info/WHEEL
    greet-1.0.dist-info/licenses/LICENSE
    greet-1.0.dist-info/sboms/greet.cdx.json
    greet-1.0.dist-info/RECORD

The :term:`sdist` holds a ``.python-sbom-revision`` file with your commit. uv built the wheel from that sdist, not from
your checkout, and the file is how the wheel still knows which commit it came from.

***************
 Read the SBOM
***************

Print a few parts of the document:

.. code-block:: console

    $ unzip -p dist/greet-1.0-py3-none-any.whl greet-1.0.dist-info/sboms/greet.cdx.json > greet.cdx.json
    $ python - <<'EOF'
    import json
    import pprint
    sbom = json.load(open('greet.cdx.json'))
    root = sbom['metadata']['component']
    print(root['name'], root['version'], root['licenses'])
    print([component['name'] for component in sbom['components']])
    print([reference['url'] for reference in root['externalReferences'] if reference['type'] == 'vcs'])
    pprint.pp(sorted(tool['name'] for tool in sbom['metadata']['tools']['components']), compact=True, width=100)
    EOF

It prints:

.. code-block:: text

    greet 1.0 [{'expression': 'MIT', 'acknowledgement': 'declared'}]
    ['packaging']
    ['https://github.com/you/greet', 'https://github.com/you/greet/tree/<your commit>']
    ['cpython', 'hatchling', 'installer', 'packageurl-python', 'packaging', 'pathspec', 'pluggy',
     'python-sbom', 'tomlkit', 'trove-classifiers', 'zipremove']

That is four things:

- the project itself, with its license;
- ``packaging``, the runtime dependency the project declares, without a version, since the installer picks it later;
- a link to your repository at the exact commit you built;
- the build tools: the interpreter, hatchling, python-sbom and every other package of the build environment.

:doc:`/concepts/document` says what each part is for.

**********
 Check it
**********

Install the command line with its ``validate`` extra and check the wheel:

.. code-block:: console

    $ uvx --from 'python-sbom[validate]' python-sbom validate dist/ --allow-license MIT
    SBOM in greet-1.0-py3-none-any.whl is valid

That is the check a CI job runs before publishing; :doc:`/how-to/validate` shows how to wire it in.

************
 Next steps
************

- Your project uses another :term:`build backend`? :doc:`/how-to/backends/index` has a guide with a complete project
  for each one python-sbom is tested with.
- Your project bundles wheels or knows more than its metadata says: :doc:`/how-to/content-provider`.
- Every option python-sbom reads: :doc:`/reference/configuration`.
