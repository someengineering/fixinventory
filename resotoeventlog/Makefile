.PHONY: clean clean-test clean-pyc clean-build clean-env docs help setup
.DEFAULT_GOAL := help
.SILENT: clean clean-build clean-pyc clean-test setup

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
	rm -fr out/
	rm -fr gen/
	rm -fr dist/
	rm -fr .eggs/
	rm -fr .hypothesis/
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
	rm -fr venv-pypy

lint: ## static code analysis
	black --line-length 120 --check resotoeventlog tests
	flake8 resotoeventlog
	mypy --python-version 3.9 --strict resotoeventlog tests

test: ## run tests quickly with the default Python
	pytest

test-all: ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source resotoeventlog -m pytest
	coverage combine
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

venv-pypy:
	pypy3.9 -m venv venv-pypy
	. ./venv-pypy/bin/activate && python3 -m pip install --upgrade pip
	. ./venv-pypy/bin/activate && pip install --upgrade --editable ../resotolib
	. ./venv-pypy/bin/activate && pip install -r requirements-test.txt
	. ./venv-pypy/bin/activate && pip install -r requirements.txt


setup: clean clean-env venv-pypy

list-outdated: 
	pip list --outdated

install-latest: 
	pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U
