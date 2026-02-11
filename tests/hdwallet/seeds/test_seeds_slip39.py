#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import logging
import os
import pytest

from hdwallet.seeds.slip39 import SLIP39Seed
from hdwallet.mnemonics.bip39 import BIP39Mnemonic


def test_slip39_seeds(data):
    
    for words in data["seeds"]["SLIP39"].keys():
        for lang in data["seeds"]["SLIP39"][words].keys():
            mnemonic = data["seeds"]["SLIP39"][words][lang]["mnemonic"]
            # A SLIP-39 "backup" for another Mnemonic (eg. BIP-39) backs up the original entropy
            # (not the derived seed, which will often be stretched to a different length).  SLIP-39
            # /can/ store 512-bit data (the output of a BIP-39 seed, after hashing it with its
            # passphrase, but this is not generally supported by hardware wallets supporting
            # SLIP-39, such as the Trezor.  This is unfortunate, as it prevents backing up BIP-39
            # derived seeds including the passphrase.
            assert SLIP39Seed.from_mnemonic(
                mnemonic = mnemonic
            ) == data["seeds"]["SLIP39"][words][lang]["non-passphrase-seed"]

