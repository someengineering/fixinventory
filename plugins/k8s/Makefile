.PHONY: clean clean-test clean-pyc clean-build docs help
.DEFAULT_GOAL := help
.SILENT: clean clean-build clean-pyc clean-test

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

lint: ## static code analysis
	black --line-length 120 --check resoto_plugin_k8s test
	flake8 resoto_plugin_k8s
	mypy --python-version 3.9 --strict resoto_plugin_k8s test

tests: ## run tests quickly with the default Python
	pytest

test-all: ## run tests on every Python version with tox
	tox

coverage: ## check code coverage quickly with the default Python
	coverage run --source resoto_plugin_k8s -m pytest
	coverage combine
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

list-outdated:
	pip list --outdated

install-latest:
	pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip install -U
