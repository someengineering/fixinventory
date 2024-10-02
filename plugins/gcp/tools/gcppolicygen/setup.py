import gcppolicygen
from setuptools import setup, find_packages


with open("requirements.txt") as f:
    requirements = f.read().splitlines()

with open("README.md") as f:
    readme = f.read()


setup(
    name=gcppolicygen.__title__,
    version=gcppolicygen.__version__,
    description=gcppolicygen.__description__,
    license=gcppolicygen.__license__,
    packages=find_packages(),
    long_description=readme,
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "gcppolicygen = gcppolicygen.__main__:main",
        ]
    },
    include_package_data=True,
    zip_safe=False,
    install_requires=requirements,
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    classifiers=[
        # Current project status
        "Development Status :: 4 - Beta",
        # Audience
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        # License information
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        # Supported python versions
        "Programming Language :: Python :: 3.12",
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
)
