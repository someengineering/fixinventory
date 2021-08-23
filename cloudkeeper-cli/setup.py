import cloudkeeper_cli
from setuptools import setup, find_packages


requirements = []
with open("requirements.txt") as f:
    requirements = f.read().splitlines()

readme = ""
with open("README.md") as f:
    readme = f.read()


setup(
    name=cloudkeeper_cli.__title__,
    version=cloudkeeper_cli.__version__,
    description=cloudkeeper_cli.__description__,
    license=cloudkeeper_cli.__license__,
    packages=find_packages(),
    long_description=readme,
    entry_points={
        "console_scripts": [
            "ck = cloudkeeper_cli.__main__:main",
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
        "License :: OSI Approved :: Apache Software License",
        # Supported python versions
        "Programming Language :: Python :: 3.8",
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
