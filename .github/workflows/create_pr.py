import os

# This script generates a github action workflow to build and check every plugin and core in parallel.
# Note: once github actions support anchors or repeated job definitions, we can get rid of this approach...

head = """
# Note: this workflow is automatically generated via the `create_pr` script in the same folder.
# Please do not change the file, but the script!

name: Check Pull Request
on:
  - push
jobs:
"""
install = """
  @name@:
    name: "@name@"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
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
          pip install --upgrade --editable cloudkeeper/
          pip install tox wheel flake8
      - name: Install cloudkeeper
        working-directory: ./cloudkeeper
        run: |
          sudo rm -fr /build
          sudo mkdir -p /build -m a+rw
          pip wheel -w /build ."""

step_aws = """
      - name: Install aws
        working-directory: ./plugins/aws
        run: pip wheel -w /build -f /build ."""

step_run_test = """
      - name: Run tests
        working-directory: @directory@
        run: tox"""


print(head)
print(install.replace("@name@", "cloudkeeper").replace("@directory@", f"cloudkeeper"))
dir = "/Users/matthias/Documents/Work/someeng/cloudkeeper/plugins"
for plugin in os.listdir(dir):
    if os.path.isdir(os.path.join(dir, plugin)):
        print(install.replace("@name@", plugin))
        # aws is a dependency that needs to be installed for all aws related plugins.
        if "aws" in plugin and "aws" != plugin:
            print(step_aws)
        print(step_run_test.replace("@directory@", f"./plugins/{plugin}"))
