.PHONY: clean, setup, requirements

clean:
	find . -type d -name 'venv' -prune -o -type d -name 'build' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name 'out' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name 'gen' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name 'dist' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '.eggs' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '.hypothesis' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '.mypy_cache' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '__pycache__' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '*.pyc' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '*.pyo' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '.tox' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '.coverage' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name 'htmlcov' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name 'pytest_cache' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type d -name '*.egg-info' -exec rm -rf {} +
	find . -type d -name 'venv' -prune -o -type f -name '*.egg' -exec rm {} +


setup: clean
	rm -rf venv
	./setup_venv.sh --dev --path .

requirements:
	python3 tools/requirements.py
