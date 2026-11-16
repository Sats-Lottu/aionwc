"""Sphinx configuration for the aionwc documentation."""

from importlib.metadata import version as distribution_version

project = "aionwc"
author = "Sats-Lottu"
copyright = f"2026, {author}"
release = distribution_version(project)
language = "en"

extensions = ["sphinx.ext.autodoc"]
autodoc_member_order = "bysource"
autodoc_typehints_format = "short"
exclude_patterns = ["_build"]

html_theme = "furo"
html_title = f"{project} {release}"
html_theme_options = {
    "light_css_variables": {
        "color-brand-primary": "#4338A8",
        "color-brand-content": "#4338A8",
    },
    "dark_css_variables": {
        "color-brand-primary": "#BAB5FF",
        "color-brand-content": "#BAB5FF",
    },
}
