#!/usr/bin/env python3
import os

# This script generates a github action workflow to build and check every plugin and core in parallel.
# Note: once github actions support anchors or repeated job definitions, we can get rid of this approach...

install = """# Note: this workflow is automatically generated via the `create_pr` script in the same folder.
# Please do not change the file, but the script!

name: Check PR (Plugin @name@)
on:
  push:
    tags:
      - "*.*.*"
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
          key: $\{\{runner.os}}-pip-$\{\{hashFiles('setup.py')}}
          restore-keys: |
            $\{\{ runner.os }}-pip-

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install --upgrade --editable resotolib/
          pip install tox wheel flake8 build
"""

aws_plugin = """
          pip install --upgrade --editable plugins/aws/
"""

step_run_test = """
      - name: Run tests
        working-directory: @directory@
        run: tox

      - name: Archive code coverage results
        uses: actions/upload-artifact@v2
        with:
          name: plugin-@name@-code-coverage-report
          path: @directory@/htmlcov/

      - name: Build a binary wheel and a source tarball
        working-directory: @directory@
        run: >-
          python -m
          build
          --sdist
          --wheel
          --outdir dist/

      - name: Publish distribution to PyPI
        if: github.ref_type == 'tag'
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          user: __token__
          password: ${{ secrets.PYPI_@PKGNAME@ }}
          packages_dir: @directory@/dist/
"""


plugins_path = os.path.abspath(
    os.path.dirname(os.path.abspath(__file__)) + "/../../plugins"
)
for plugin in os.listdir(plugins_path):
    if os.path.isdir(os.path.join(plugins_path, plugin)):
        with open(f"check_pr_plugin_{plugin}.yml", "w") as yml:
            yml.write(install.replace("@name@", plugin).replace("@PKGNAME@", f"resoto_plugin_{plugin}".upper()))
            if "_aws_" in plugin:
                yml.write(aws_plugin)
            yml.write(
                step_run_test.replace("@directory@", f"./plugins/{plugin}").replace(
                    "@name@", plugin
                ).replace("@PKGNAME@", f"resoto_plugin_{plugin}".upper())
            )
