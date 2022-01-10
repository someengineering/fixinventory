.PHONY: clean clean-test clean-pyc clean-build clean-env docs help setup
.DEFAULT_GOAL := help
.SILENT: clean clean-build clean-pyc clean-test setup venv

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test ## remove all build, test, coverage and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr .mypy_cache/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -fr {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

clean-env: ## remove environment
	rm -fr venv
	rm -fr venv-pypy

lint: venv ## check style with flake8
	black --line-length 120 --check core tests
	flake8 core
	pylint core
	mypy --python-version 3.8 --strict core tests

test: venv ## run tests quickly with the default Python
	pytest

test-all: venv ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source core -m pytest
	coverage combine
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

release: dist ## package and upload a release
	twine upload dist/*

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean ## install the package to the active Python's site-packages
	python setup.py install

venv-pypy:
	pypy3.8 -m venv venv-pypy
	. ./venv-pypy/bin/activate && python3 -m pip install --upgrade pip
	. ./venv-pypy/bin/activate && pip install --upgrade --editable ../cklib
	. ./venv-pypy/bin/activate && pip install -r requirements-test.txt
	. ./venv-pypy/bin/activate && pip install -r requirements.txt


venv:
	python3 -m venv venv --prompt "ckcore env"
	. ./venv/bin/activate && python3 -m pip install --upgrade pip
	. ./venv/bin/activate && pip install --upgrade --editable ../cklib
	. ./venv/bin/activate && pip install -r requirements-dev.txt
	. ./venv/bin/activate && pip install -r requirements-test.txt
	. ./venv/bin/activate && pip install -r requirements.txt
	. ./venv/bin/activate && mypy --python-version 3.8 core tests > /dev/null 2>&1 || true
	echo "Run mypy once to collect all required types and packages..."
	. ./venv/bin/activate && mypy --python-version 3.8 --install-types --non-interactive core tests || true
	printf "Consider to execute in your running shell:\n\nPYTHONPATH=`pwd`\nsource venv/bin/activate\n\n"

setup: clean clean-env venv

list-outdated: venv
	pip list --outdated

install-latest: venv
	pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U
