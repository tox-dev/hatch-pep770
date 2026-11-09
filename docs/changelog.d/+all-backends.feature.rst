Write the SBOM with any build backend: a pdm-backend hook and a setuptools plugin act for every project with a
``[tool.python-sbom]`` table, and ``python_sbom.backend`` wraps any other backend, such as meson-python or maturin, named
by the new ``build-backend`` option. Each records the source revision in the sdist, as the hatchling hook does.
