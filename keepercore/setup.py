#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('requirements.txt') as f:
    required = f.read().splitlines()

with open('requirements-dev.txt') as f:
    test_required = f.read().splitlines()

with open('README.md') as f:
    readme = f.read()

setup_requirements = ['pytest-runner', ]

setup(
    name='keepercore',
    version='0.1.0',
    description="Keeps all the things.",
    python_requires='>=3.5',
    classifiers=['Programming Language :: Python :: 3'],
    entry_points={ 'console_scripts': ['keepercore=core.__main__:main']},
    install_requires=required,
    license="Apache Software License 2.0",
    long_description=readme,
    include_package_data=True,
    packages=find_packages(include=['core', 'core.*']),
    setup_requires=setup_requirements,
    test_suite='tests',
    tests_require=test_required,
    url='https://github.com/someengineering/keepercore',
)
