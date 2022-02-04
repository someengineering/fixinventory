#!/usr/bin/env python3
import os

# This script generates a github action workflow to build and check every plugin and core in parallel.
# Note: once github actions support anchors or repeated job definitions, we can get rid of this approach...

install = """# Note: this workflow is automatically generated via the `create_pr` script in the same folder.
# Please do not change the file, but the script!

name: Check PR (Plugin @name@)
on:
  push:
    branches:
        - main
  pull_request:
    paths:
      - 'resotolib/**'
      - 'plugins/@name@/**'
      - '.github/**'

jobs:
  @name@:
    name: "@name@"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
          architecture: 'x64'

      - name: Restore dependency cache
        uses: actions/cache@v2
        with:
          path: ~/.cache/pip
          key: $\{\{runner.os}}-pip-$\{\{hashFiles('pyproject.toml')}}
          restore-keys: |
            $\{\{ runner.os }}-pip-

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install poetry nox
          poetry install
"""

step_run_test = """
      - name: Run tests
        working-directory: @directory@
        run: nox

      - name: Archive code coverage results
        uses: actions/upload-artifact@v2
        with:
          name: plugin-@name@-code-coverage-report
          path: @directory@/htmlcov/
"""


plugins_path = os.path.abspath(
    os.path.dirname(os.path.abspath(__file__)) + "/../../plugins"
)
for plugin in os.listdir(plugins_path):
    if os.path.isdir(os.path.join(plugins_path, plugin)):
        with open(f"check_pr_plugin_{plugin}.yml", "w") as yml:
            yml.write(install.replace("@name@", plugin))
            yml.write(
                step_run_test.replace("@directory@", f"./plugins/{plugin}").replace(
                    "@name@", plugin
                )
            )
