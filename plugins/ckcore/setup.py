import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name="cloudkeeper-plugin-ckcore",
    version="2.0.0a1",
    description="Cloudkeeper ckcore Plugin",
    license="Apache 2.0",
    packages=find_packages(),
    long_description=read("README.md"),
    entry_points={
        "cloudkeeper.plugins": ["ckcore = cloudkeeper_plugin_ckcore:CkCorePlugin"]
    },
    include_package_data=True,
    zip_safe=False,
    install_requires=["cklib"],
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
