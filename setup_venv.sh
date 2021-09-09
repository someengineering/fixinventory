#!/bin/bash
if [ -d "venv/" ]; then
    echo -e "Virtual Python ENV already exists!\nRun:\n\trm -rf venv/\nif you want to recreate it"
    exit 1
fi
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r keepercore/requirements-dev.txt
pip install --editable keepercore/
pip install --editable keeper-cli/
pip install --editable graph_exporter/
pip install --editable cloudkeeper/
pip install --editable plugins/aws/
find plugins/ -maxdepth 1 -mindepth 1 -type d -exec pip install --editable "{}" \;
