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
      - 'fixlib/**'
      - 'plugins/@name@/**'
      - '.github/**'
      - 'requirements-all.txt'

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
  cancel-in-progress: true

jobs:
  @name@:
    name: "@name@"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          architecture: 'x64'

      - name: Restore dependency cache
        uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: ${{runner.os}}-pip-${{hashFiles('@directory@/pyproject.toml')}}
          restore-keys: |
            ${{runner.os}}-pip-

      - name: Install Dependencies
        run: |
          python -m pip install --upgrade pip
          pip install --upgrade --editable fixlib/
          pip install tox wheel flake8 build
"""

aws_plugin = """
          pip install --upgrade --editable plugins/aws/
"""

aws_policygen = """
      - name: Upload AWS policies
        if: github.event_name != 'pull_request'
        working-directory: ./plugins/aws
        run: |
          pip install --upgrade --editable .
          pip install --upgrade --editable ./tools/awspolicygen
          export GITHUB_REF="${{ github.ref }}"
          export GITHUB_REF_TYPE="${{ github.ref_type }}"
          export GITHUB_EVENT_NAME="${{ github.event_name }}"
          export API_TOKEN="${{ secrets.API_TOKEN }}"
          export SPACES_KEY="${{ secrets.SPACES_KEY }}"
          export SPACES_SECRET="${{ secrets.SPACES_SECRET }}"
          export AWS_ACCESS_KEY_ID="${{ secrets.S3_FIXINVENTORYPUBLIC_AWS_ACCESS_KEY_ID }}"
          export AWS_SECRET_ACCESS_KEY="${{ secrets.S3_FIXINVENTORYPUBLIC_AWS_SECRET_ACCESS_KEY }}"
          awspolicygen --verbose --spaces-name somecdn --spaces-region ams3 --spaces-path fix/aws/ --aws-s3-bucket fixinventorypublic --aws-s3-bucket-path cf/
"""

gcp_policygen = """
      - name: Upload GCP policies
        if: github.event_name != 'pull_request'
        working-directory: ./plugins/gcp
        run: |
          pip install --upgrade --editable .
          pip install --upgrade --editable ./tools/gcppolicygen
          export GITHUB_REF="${{ github.ref }}"
          export GITHUB_REF_TYPE="${{ github.ref_type }}"
          export GITHUB_EVENT_NAME="${{ github.event_name }}"
          export API_TOKEN="${{ secrets.API_TOKEN }}"
          export SPACES_KEY="${{ secrets.SPACES_KEY }}"
          export SPACES_SECRET="${{ secrets.SPACES_SECRET }}"
          gcppolicygen --verbose --spaces-name somecdn --spaces-region ams3 --spaces-path fix/gcp/
"""

step_run_test = """
      - name: Run tests
        working-directory: @directory@
        run: tox

      - name: Archive code coverage results
        uses: actions/upload-artifact@v4
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


plugins_path = os.path.abspath(os.path.dirname(os.path.abspath(__file__)) + "/../../plugins")
for plugin in os.listdir(plugins_path):
    if os.path.isdir(os.path.join(plugins_path, plugin)):
        with open(f"check_pr_plugin_{plugin}.yml", "w") as yml:
            yml.write(
                install.replace("@directory@", f"./plugins/{plugin}")
                .replace("@name@", plugin)
                .replace("@PKGNAME@", f"fixinventory_plugin_{plugin}".upper())
            )
            if "_aws_" in plugin:
                yml.write(aws_plugin)
            yml.write(
                step_run_test.replace("@directory@", f"./plugins/{plugin}")
                .replace("@name@", plugin)
                .replace("@PKGNAME@", f"fixinventory_plugin_{plugin}".upper())
            )
            if plugin == "aws":
                yml.write(aws_policygen)
            elif plugin == "gcp":
                yml.write(gcp_policygen)
