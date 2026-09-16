#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.monero import MoneroSeed


def test_monero_seeds(data):
    
    for words in data["seeds"]["Monero"].keys():
        for lang in data["seeds"]["Monero"][words].keys():
            assert MoneroSeed.from_mnemonic(
                mnemonic=data["seeds"]["Monero"][words][lang]["mnemonic"]
            ) == data["seeds"]["Monero"][words][lang]["non-passphrase-seed"]

