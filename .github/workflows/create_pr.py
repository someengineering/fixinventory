import os

head = """
name: Check Pull Request
on:
  - push
jobs:
"""
tpl = """
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
          pip wheel -w /build .
      - name: Install aws
        working-directory: ./plugins/aws
        run: pip wheel -w /build -f /build .
      - name: Run tests
        working-directory: @directory@
        run: tox
"""

print(head)
print(tpl.replace("@name@", "cloudkeeper").replace("@directory@", f"cloudkeeper"))
dir = "/Users/matthias/Documents/Work/someeng/cloudkeeper/plugins"
for plugin in os.listdir(dir):
    if os.path.isdir(os.path.join(dir, plugin)):
        print(tpl.replace("@name@", plugin).replace("@directory@", f"plugin/{plugin}"))
