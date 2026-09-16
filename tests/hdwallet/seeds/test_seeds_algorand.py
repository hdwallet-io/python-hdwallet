#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.algorand import AlgorandSeed


def test_algorand_seeds(data):
    assert AlgorandSeed.from_mnemonic(
        mnemonic=data["seeds"]["Algorand"]["25"]["english"]["mnemonic"]
    ) == data["seeds"]["Algorand"]["25"]["english"]["non-passphrase-seed"]

