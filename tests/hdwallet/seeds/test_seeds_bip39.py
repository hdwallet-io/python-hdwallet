#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.bip39 import BIP39Seed


def test_bip39_seeds(data):
    
    for words in data["seeds"]["BIP39"].keys():
        for lang in data["seeds"]["BIP39"][words].keys():
            assert BIP39Seed.from_mnemonic(
                mnemonic= data["seeds"]["BIP39"][words][lang]["mnemonic"]
            ) == data["seeds"]["BIP39"][words][lang]["non-passphrase-seed"]

            for passphrase in data["seeds"]["BIP39"][words][lang]["passphrases"].keys():
                assert BIP39Seed.from_mnemonic(
                    mnemonic= data["seeds"]["BIP39"][words][lang]["mnemonic"], passphrase=passphrase
                ) == data["seeds"]["BIP39"][words][lang]["passphrases"][passphrase]
