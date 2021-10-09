#!/bin/bash
set -euo pipefail

SUPPORTED_VERSIONS="python3.9 python3.8 python3.7"

main() {
    echo "Cloudkeeper venv/ bootstrapper."
    local python_cmd
    python_cmd="$(find_python)"
    if [ -z "$python_cmd" ]; then
        echo -e "Could not find a compatible Python interpreter!\nSupported versions are $SUPPORTED_VERSIONS"
        exit 1
    fi
    echo -e "Using $python_cmd\n"
    activate_venv "$python_cmd"
    ensure_pip
    install_cloudkeeper
    install_plugins
    echo -e "Install/Update completed.\nRun\n\tsource venv/bin/activate\nto activate venv."
}

find_python() {
    local version
    for version in $SUPPORTED_VERSIONS; do
        if type "$version" > /dev/null 2>&1; then
            echo "$version"
            return 0
        fi
    done
    return 1
}

activate_venv() {
    local python_cmd=$1
    echo "Creating virtual Python env in venv/ using $python_cmd"
    if [ -d "venv/" ]; then
        echo -e "Virtual Python env already exists!\nRun\n\trm -rf venv/\nif you want to recreate it.\n"
    else
        "$python_cmd" -m venv venv
    fi
    source venv/bin/activate
}

ensure_pip() {
    echo "Ensuring Python pip is available and up to date."
    if ! python -m pip help > /dev/null 2>&1; then
        python -m ensurepip -U
    fi
    pip install -U pip
    echo
}

install_cloudkeeper() {
    echo "Installing Cloudkeeper"
    local cloudkeeper_components="cklib ckcore cksh ckworker ckmetrics"
    for component in $cloudkeeper_components; do
        pip_install "$component"
    done
}

install_plugins() {
    local collector_plugins="aws gcp slack onelogin k8s onprem github example_collector"
    for plugin in $collector_plugins; do
        pip_install "$plugin" true
    done
}

ensure_git() {
    if ! type git > /dev/null 2>&1; then
        echo "Git is not available in PATH - aborting install"
        exit 1
    fi
}

pip_install() {
    local package=$1
    local plugin=${2:-false}
    local egg_prefix=""
    local path_prefix=""
    if [ "$plugin" = true ]; then
        path_prefix="plugins/"
        egg_prefix="cloudkeeper-plugin-"
    fi
    local package_name="${egg_prefix}${package}"
    package_name=${package_name//_/-}
    local relative_path="${path_prefix}${package}/"
    if [ -d "$relative_path" ]; then
        echo "Installing $package_name editable from local path $relative_path"
        pip install --editable "$relative_path"
    else
        ensure_git
        local git_repo="git+https://github.com/someengineering/cloudkeeper.git@main#egg=${package_name}&subdirectory=${relative_path}"
        echo "Installing $package_name editable from remote Git $git_repo"
        pip install -U "$git_repo"
    fi
}

main
