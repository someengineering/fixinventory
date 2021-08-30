#!/bin/bash
if [ -d "venv/" ]; then
    echo "Virtual Python ENV already exists - rm -rf venv/ - if you want to recreate it"
    exit 1
fi
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install --editable keepercore/
pip install --editable keeper-cli/
pip install --editable cloudkeeper/
pip install --editable plugins/aws/
find plugins/ -maxdepth 1 -mindepth 1 -type d -exec pip install --editable "{}" \;
