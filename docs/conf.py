"""Documentation generation configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from tomllib import loads
from typing import TYPE_CHECKING, Final

import python_sbom
from python_sbom import __version__

if TYPE_CHECKING:
    from docutils.nodes import Element, reference
    from sphinx.addnodes import pending_xref
    from sphinx.application import Sphinx
    from sphinx.environment import BuildEnvironment


def _inheritance_aliases() -> dict[str, str]:
    aliases: dict[str, str] = {}
    for entry in python_sbom.__all__:
        to_module = getattr(getattr(python_sbom, entry), "__module__", "")
        # first instance wins
        aliases.setdefault(f"{to_module}{'.' if to_module else ''}{entry}", f"{python_sbom.__name__}.{entry}")
    return aliases


project: Final[str] = "python-sbom"
_NOW: Final[datetime] = datetime.now(tz=UTC)
globals()["copyright"] = f"2026-{_NOW.year}"
version: Final[str] = __version__
release: Final[str] = __version__.split("+")[0]

extensions: Final[list[str]] = [
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.autodoc",
    "sphinx.ext.extlinks",
    "sphinx.ext.intersphinx",
    "sphinx.ext.inheritance_diagram",
    "sphinx_argparse_cli",
    "sphinx_autodoc_typehints",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinx_inline_tabs",
    "sphinxcontrib.mermaid",
]

master_doc: Final[str] = "index"
source_suffix: Final[str] = ".rst"
exclude_patterns: Final[list[str]] = ["changelog.d/*"]
autosectionlabel_maxdepth: Final[int] = 2
autosectionlabel_prefix_document: Final[bool] = True

html_theme: Final[str] = "furo"
html_title: Final[str] = "python-sbom: SBOMs for Python distributions"
html_last_updated_fmt: Final[str] = _NOW.isoformat()
html_static_path: Final[list[str]] = ["_static"]
html_favicon: Final[str] = "_static/favicon.svg"
html_theme_options: Final[dict[str, str | bool | dict[str, str]]] = {
    "source_repository": "https://github.com/tox-dev/python-sbom",
    "source_branch": "main",
    "source_directory": "docs/",
    "light_logo": "logo-light.svg",
    "dark_logo": "logo-dark.svg",
    "sidebar_hide_name": True,
    "light_css_variables": {
        "color-brand-primary": "#2b6599",
        "color-brand-content": "#2b6599",
        "color-brand-visited": "#2b6599",
        "font-stack": "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif",
        "font-stack--monospace": "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
        # top-level entries take the text color, so only the branch holding the current page shows the brand color
        "color-sidebar-link-text--top-level": "#1f2937",
        # Furo's grays read washed out in the small sidebar and contents text; its dark palette sets both already
        "color-foreground-secondary": "#3b3f46",
        "color-foreground-muted": "#4a4f57",
        # a near-black on off-white reads at 15:1 without the glare of pure black on white
        "color-foreground-primary": "#1e2329",
        "color-background-primary": "#fcfcfb",
        "color-foreground-border": "#63676f",
    },
    "dark_css_variables": {
        # the logo's yellow, toned down a step so links and the current page do not glare on the navy
        "color-brand-primary": "#f0c94a",
        "color-brand-content": "#f0c94a",
        "color-brand-visited": "#f0c94a",
        "color-background-primary": "#0b1626",
        "color-background-secondary": "#0f1e33",
        "color-background-hover": "#14273f",
        "color-background-border": "#1f3654",
        "color-sidebar-link-text--top-level": "#d6dde8",
        "color-foreground-border": "#8a96a8",
    },
}
html_css_files: Final[list[str]] = ["changelog-toc.css", "python-sbom.css"]
# copying a snippet takes the command alone, not the console prompt or its output
copybutton_exclude: Final[str] = ".linenos, .gp, .go"
# the browser renders each diagram, so it follows furo's light and dark toggle
mermaid_output_format: Final[str] = "raw"
mermaid_light_theme: Final[str] = "neutral"
# the default fixed 500px height pads a wide diagram with empty bands
mermaid_height: Final[str] = "auto"
# both pass WCAG AA (4.5:1) for every token color against their own background
pygments_style: Final[str] = "xcode"
pygments_dark_style: Final[str] = "github-dark"

autoclass_content: Final[str] = "both"
inheritance_alias: Final[dict[str, str]] = _inheritance_aliases()
inheritance_graph_attrs: Final[dict[str, str]] = {"rankdir": "TB"}
# each directive names the members it documents, so hatchling's lifecycle methods and inherited members stay out
autodoc_default_options: Final[dict[str, bool | str]] = {"member-order": "bysource", "show-inheritance": True}
typehints_fully_qualified: Final[bool] = False
always_document_param_types: Final[bool] = True
typehints_document_rtype: Final[bool] = True
typehints_defaults: Final[str] = "comma"

intersphinx_mapping: Final[dict[str, tuple[str, None]]] = {"python": ("https://docs.python.org/3.11", None)}
extlinks: Final[dict[str, tuple[str, str]]] = {
    "pr": ("https://github.com/tox-dev/python-sbom/pull/%s", "#%s"),
    "user": ("https://github.com/%s", "@%s"),
}
nitpicky: Final[bool] = True
nitpick_ignore: Final[list[tuple[str, str]]] = [
    # hatchling publishes no Sphinx inventory
    ("py:class", "hatchling.builders.hooks.plugin.interface.BuildHookInterface"),
    ("py:class", "hatchling.metadata.core.ProjectMetadata"),
    ("py:class", "hatchling.bridge.app.Application"),
    # neither pdm-backend nor setuptools publishes these in a Sphinx inventory
    ("py:class", "pdm.backend.hooks.base.Context"),
    ("py:class", "Context"),
    ("py:class", "setuptools.dist.Distribution"),
    ("py:class", "Distribution"),
    ("py:class", "ConfigSettings"),
]


def setup(app: Sphinx) -> None:
    # annotations name the private modules that define a type, and pathlib.Path an undocumented private alias
    app.connect("missing-reference", _resolve_private_path)
    app.connect("source-read", _include_unreleased)


def _resolve_private_path(
    app: Sphinx,
    env: BuildEnvironment,
    node: pending_xref,
    contnode: Element,
) -> reference | None:
    module, _, name = node["reftarget"].rpartition(".")
    if node["reftarget"] == "pathlib._local.Path":
        node["reftarget"] = "pathlib.Path"
    elif module.startswith("python_sbom._") and name in python_sbom.__all__:
        node["reftarget"] = f"python_sbom.{name}"
    else:
        return None
    domain = env.get_domain("py")
    return domain.resolve_xref(env, node["refdoc"], app.builder, node["reftype"], node["reftarget"], node, contnode)


def _include_unreleased(app: Sphinx, docname: str, source: list[str]) -> None:
    if docname != "changelog":
        return
    root = Path(__file__).parent.parent
    fragments = root / "docs" / "changelog.d"
    app.env.note_dependency(str(fragments))
    sections: list[str] = []
    for category in loads((root / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["towncrier"]["type"]:
        entries = [
            f"- {' '.join(fragment.read_text(encoding='utf-8').split())}"
            for fragment in sorted(fragments.glob(f"*.{category['directory']}.rst"))
        ]
        if entries:
            sections.extend((
                f".. _release-unreleased-{category['name'].lower().replace(' ', '-')}:",
                "",
                category["name"],
                "~" * len(category["name"]),
                "",
                *entries,
                "",
            ))
    if sections:
        joined = "\n".join(sections)
        source[0] = source[0].replace(
            ".. towncrier release notes start",
            f".. _release-unreleased:\n\nUnreleased\n----------\n\n{joined}\n.. towncrier release notes start",
        )
