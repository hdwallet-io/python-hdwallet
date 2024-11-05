#!/usr/bin/env python3

from setuptools import (
    setup, find_packages
)

# Project URLs
project_urls = {
    "Tracker": "https://github.com/meherett/python-hdwallet/issues",
    "Documentation": "https://hdwallet.readthedocs.io"
}

# README.md
with open( "README.md", "r", encoding="utf-8") as readme:
    long_description: str = readme.read()
with open( "requirements.txt" ) as r:
    install_requires: list = list( r.readlines() )
with open( "requirements-tests.txt" ) as rt:
    tests_require: list	= list( rt.readlines() )
extras_require: dict		= {
    option: list(
        # Remove whitespace, elide blank lines and comments
        ''.join( r.split() )
        for r in open( f"requirements-{option}.txt" ).readlines()
        if r.strip() and not r.strip().startswith( '#' )
    )
    for option in ('cli', 'tests', 'docs')
}
with open( "hdwallet/version.py" ) as vpy:
    exec( vpy.read() )

setup(
    name="hdwallet",
    version=__version__,
    description="Python-based library for the implementation of a hierarchical deterministic wallet "
                "generator for more than 140+ multiple cryptocurrencies.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Meheret Tesfaye Batu",
    author_email="meherett.batu@gmail.com",
    url="https://github.com/meherett/python-hdwallet",
    project_urls=project_urls,
    keywords=[
        "cryptography", "cli", "wallet", "bip32", "bip44", "bip39", "hdwallet", "cryptocurrencies", "bitcoin", "ethereum"
    ],
    entry_points={
        "console_scripts": ["hdwallet=hdwallet.cli.__main__:main"]
    },
    python_requires=">=3.6,<4",
    packages=find_packages(),
    install_requires=install_requires,
    extras_require=extras_require,
    tests_require=tests_require,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ]
)
