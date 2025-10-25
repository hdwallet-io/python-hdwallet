#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import List

__name__: str = "hdwallet"
__version__: str = "v3.7.0"
__license__: str = "MIT"
__author__: str = "Meheret Tesfaye Batu"
__email__: str = "meherett.batu@gmail.com"
__documentation__: str = "https://hdwallet.readthedocs.com"
__description__: str = "Python-based library implementing a Hierarchical Deterministic (HD) Wallet generator for 200+ cryptocurrencies."
__url__: str = "https://hdwallet.io"
__source__: str = "https://github.com/hdwallet-io/python-hdwallet"
__changelog__: str = f"{__source__}/blob/master/CHANGELOG.md"
__tracker__: str = f"{__source__}/issues"
__keywords__: List[str] = [
    "ecc", "kholaw", "slip10", "ed25519", "nist256p1", "secp256k1",  # ECC keywords
    "hd", "bip32", "bip44", "bip49", "bip84", "bip86", "bip141", "monero", "cardano",  # HD keywords
    "entropy", "mnemonic", "seed", "bip39", "slip39", "algorand", "electrum",  # Entropy, Mnemonic and Seed keywords
    "cryptocurrencies", "bitcoin", "ethereum", "cryptography", "cli", "cip1852"  # Other keywords
]
__websites__: List[str] = [
    "https://talonlab.org",
    "https://talonlab.gitbook.io/hdwallet",
    __documentation__,
    "https://hdwallet.online",
    "https://hd.wallet",  # On Web3 domain
    __url__
]
