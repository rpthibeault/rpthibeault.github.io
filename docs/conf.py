# Configuration file for the Sphinx documentation builder.

# -- Project information -----------------------------------------------------
project = '~rpthibeault'
copyright = '2025, Raphaël Pinsonneault-Thibeault'
author = 'Raphaël Pinsonneault-Thibeault'

# -- General configuration ---------------------------------------------------
extensions = [
    'myst_parser',  # For Markdown support
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'alabaster'
html_static_path = ['_static']
html_title = '~rpthibeault'

# -- MyST Parser configuration -----------------------------------------------
myst_enable_extensions = [
    "colon_fence",
    "deflist",
]
