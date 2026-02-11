#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import List
from setuptools import (
    setup, find_packages
)

import importlib.util


# requirements/{name}.txt
def get_requirements(name: str) -> List[str]:
    with open(f"{name}.txt", "r") as requirements:
        return list(filter(None, map(str.strip, requirements.read().split("\n"))))


# README.md
with open("README.md", "r", encoding="utf-8") as readme:
    long_description: str = readme.read()

# hdwallet/info.py
spec = importlib.util.spec_from_file_location(
    "info", "hdwallet/info.py"
)
info = importlib.util.module_from_spec(spec)
spec.loader.exec_module(info)

setup(
    name=info.__name__,
    version=info.__version__,
    description=info.__description__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=info.__license__,
    author=info.__author__,
    author_email=info.__email__,
    url=info.__url__,
    project_urls={
        "Tracker": info.__tracker__,
        "Source": info.__source__,
        "Changelog": info.__changelog__,
        "Documentation": info.__documentation__
    },
    keywords=info.__keywords__,
    entry_points=dict(
        console_scripts=[
            "hdwallet=hdwallet.cli.__main__:cli_main"
        ]
    ),
    python_requires=">=3.9,<4",
    packages=find_packages(exclude=["tests*"]),
    install_requires=get_requirements(name="requirements"),
    include_package_data=True,
    extras_require=dict(
        cli=get_requirements(name="requirements/cli"),
        docs=get_requirements(name="requirements/docs"),
        tests=get_requirements(name="requirements/tests")
    ),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
