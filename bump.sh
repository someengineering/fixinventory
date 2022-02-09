#!/bin/bash
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <bump-from> <bump-to>"
    echo "E.g. $0 '2\\.0\\.0a5' 2.0.0a6"
    exit 1
fi

bump_from=$1
bump_to=$2
find resotolib \
        resotocore \
        resotoworker \
        resotoshell \
        resotometrics \
        plugins \
    -name pyproject.toml -o \
    -name poetry.lock \
| xargs grep "$bump_from" \
| cut -d : -f 1 \
| xargs sed -i -e "s/$bump_from/$bump_to/g"
git status
git diff
