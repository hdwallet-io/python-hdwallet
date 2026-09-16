#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.electrum.v2 import ElectrumV2Seed


def test_electrum_v2_seeds(data):
    
    for words in data["seeds"]["Electrum-V2"].keys():
        for mnemonic_type in data["seeds"]["Electrum-V2"][words].keys():

            for lang in data["seeds"]["Electrum-V2"][words][mnemonic_type].keys():
                assert ElectrumV2Seed.from_mnemonic(
                    mnemonic= data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["mnemonic"], mnemonic_type=mnemonic_type
                ) == data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["non-passphrase-seed"]

                for passphrase in data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["passphrases"].keys():
                    assert ElectrumV2Seed.from_mnemonic(
                        mnemonic=data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["mnemonic"],
                        passphrase=passphrase,
                        mnemonic_type=mnemonic_type
                    ) == data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["passphrases"][passphrase]

                    assert ElectrumV2Seed.from_mnemonic(
                        mnemonic=data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["mnemonic"],
                        passphrase=passphrase,
                        mnemonic_type=mnemonic_type
                    ) == data["seeds"]["Electrum-V2"][words][mnemonic_type][lang]["passphrases"][passphrase]

