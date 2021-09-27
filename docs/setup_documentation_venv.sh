#!/bin/bash
set -euo pipefail

if [ -d "venv/" ]; then
    echo -e "Virtual Python ENV already exists!\nRun:\n\trm -rf venv/\nif you want to recreate it"
    exit 1
fi
python3.9 -m venv venv --prompt "CK Docs"
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
