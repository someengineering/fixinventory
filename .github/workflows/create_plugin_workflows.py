import os

# This script generates a github action workflow to build and check every plugin and core in parallel.
# Note: once github actions support anchors or repeated job definitions, we can get rid of this approach...

install = """# Note: this workflow is automatically generated via the `create_pr` script in the same folder.
# Please do not change the file, but the script!

name: Check PR (Plugin @name@)
on:
  push:
    paths:
      - 'cklib/**'
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
          python-version: '3.9'
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
          pip install --upgrade --editable cklib/
          pip install tox wheel flake8

      - name: Build cklib
        working-directory: ./cklib
        run: |
          sudo rm -rf /build
          sudo mkdir -p /build -m a+rw
          pip wheel -w /build .
"""

step_cloudkeeperV1 = """
      - name: Build cloudkeeperV1
        working-directory: ./cloudkeeperV1
        run: |
          pip wheel -w /build -f /build .
"""

step_aws = """
      - name: Build aws
        working-directory: ./plugins/aws
        run: pip wheel -w /build -f /build .
"""

step_run_test = """
      - name: Run tests
        working-directory: @directory@
        run: tox
"""


plugins_path = os.path.abspath(
    os.path.dirname(os.path.abspath(__file__)) + "/../../plugins"
)
for plugin in os.listdir(plugins_path):
    if os.path.isdir(os.path.join(plugins_path, plugin)):
        with open(f"check_pr_plugin_{plugin}.yml", "w") as yml:
            yml.write(install.replace("@name@", plugin))
            if plugin in ("tag_aws_ctime", "tagvalidator"):
                yml.write(step_cloudkeeperV1)
            # aws is a dependency that needs to be installed for all aws related plugins.
            if "aws" in plugin and plugin != "aws":
                yml.write(step_aws)
            yml.write(step_run_test.replace("@directory@", f"./plugins/{plugin}"))
