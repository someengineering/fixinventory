#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages
import pkg_resources
import os


def read(file_name: str) -> str:
    with open(os.path.join(os.path.dirname(__file__), file_name)) as of:
        return of.read()


def read_requirements(fname):
    return [str(requirement) for requirement in pkg_resources.parse_requirements(read(fname))]


setup_requirements = ["pytest-runner"]

setup(
    name="resotoeventlog",
    version="3.1.0",
    description="Event log aggregator for resoto.",
    python_requires=">=3.5",
    classifiers=["Programming Language :: Python :: 3"],
    entry_points={"console_scripts": ["resotoeventlog=resotoeventlog.__main__:main"]},
    install_requires=read_requirements("requirements.txt"),
    license="Apache Software License 2.0",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    include_package_data=True,
    packages=find_packages(include=["resotoeventlog", "resotoeventlog.*"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=read_requirements("requirements-dev.txt") + read_requirements("requirements-test.txt"),
    url="https://github.com/someengineering/resoto/tree/main/resotoeventlog",
)
