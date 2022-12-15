#!/bin/bash
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <bump-from> <bump-to>"
    echo "E.g. $0 '2\\.0\\.0rc1' 2.0.0rc2"
    exit 1
fi

bump_from=$1
bump_to=$2
git ls-files | grep \
    -e setup.py \
    -e __init__.py \
    -e requirements.txt \
| xargs grep "$bump_from" \
| cut -d : -f 1 \
| xargs sed -i -e "s/$bump_from/$bump_to/g"
git status
git diff
