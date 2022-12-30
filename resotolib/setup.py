import os
import resotolib
import pkg_resources
from setuptools import setup, find_packages


def read(file_name: str) -> str:
    with open(os.path.join(os.path.dirname(__file__), file_name)) as of:
        return of.read()


setup(
    name=resotolib.__title__,
    version=resotolib.__version__,
    description=resotolib.__description__,
    license=resotolib.__license__,
    packages=find_packages(),
    package_data={"resotolib": ["py.typed"]},
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    include_package_data=True,
    zip_safe=False,
    install_requires=[str(requirement) for requirement in pkg_resources.parse_requirements(read("requirements.txt"))],
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    classifiers=[
        # Current project status
        "Development Status :: 4 - Beta",
        # Audience
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        # License information
        "License :: OSI Approved :: Apache Software License",
        # Supported python versions
        "Programming Language :: Python :: 3.9",
        # Supported OS's
        "Operating System :: POSIX :: Linux",
        "Operating System :: Unix",
        # Extra metadata
        "Environment :: Console",
        "Natural Language :: English",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    keywords="cloud security",
    url="https://github.com/someengineering/resoto/tree/main/resotolib",
)
