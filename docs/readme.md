## Install Sphinx
Run `setup_documentation_venv.sh` to install `sphinx` and `sphinx_rtd_theme`.

## Building the docs
To build the docs, use the following command in the docs/ directory:

    sphinx-build -b html source/ _build/html

## Testing local
In the directory of the docs, use the following command to serve and test local:

    python -m http.server

With the server running, visit http://127.0.0.1:8000/_build/html/ in your webbrowser to check out the docs.
