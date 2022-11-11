#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open("requirements.txt") as f:
    required = f.read().splitlines()

with open("requirements-test.txt") as f:
    test_required = f.read().splitlines()

with open("README.md") as f:
    readme = f.read()

setup_requirements = [
    "pytest-runner",
]


setup(
    name="cloud2sql",
    version="1.0.0a1",
    description="Read infrastructure data from your cloud and export it to an SQL database.",
    python_requires=">=3.9",
    classifiers=["Programming Language :: Python :: 3"],
    entry_points={"console_scripts": ["cloud2sql=cloud2sql.__main__:main"]},
    install_requires=required,
    license="Apache Software License 2.0",
    long_description=readme,
    long_description_content_type="text/markdown",
    include_package_data=True,
    packages=find_packages(include=["cloud2sql", "cloud2sql.*"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_required,
    url="https://github.com/someengineering/resoto/cloud2sql",
)
