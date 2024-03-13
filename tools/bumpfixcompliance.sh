#!/bin/bash
set -euo pipefail

PACKAGE_NAME="fixcompliance"
LATEST_VERSION=$(curl -s https://pypi.org/pypi/$PACKAGE_NAME/json | jq -r '.info.version')

if [ -z "$LATEST_VERSION" ]; then
    echo "Failed to fetch the latest version of $PACKAGE_NAME"
    exit 1
fi

PATTERN="$PACKAGE_NAME=="
NEW_VERSION="$PACKAGE_NAME==$LATEST_VERSION"
CURRENT_VERSION=$(grep "^$PATTERN" requirements.txt | sed "s/$PATTERN//")

if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
    echo "$PACKAGE_NAME is already up to date"
    exit 2
fi

for requirements_file in requirements.txt requirements-all.txt requirements-extra.txt
do
    sed -i "s/${PATTERN}[0-9a-zA-Z.-]*/$NEW_VERSION/" "$requirements_file"
    echo "Updated $PACKAGE_NAME to version $LATEST_VERSION in $requirements_file"
done
