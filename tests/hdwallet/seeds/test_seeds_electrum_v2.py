#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
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

            for language in data["seeds"]["Electrum-V2"][words][mnemonic_type].keys():
                mnemonic = data["seeds"]["Electrum-V2"][words][mnemonic_type][language]["mnemonic"]
                non_passphrase_seed = ElectrumV2Seed.from_mnemonic(
                    mnemonic=mnemonic,
                    language=language,
                    mnemonic_type=mnemonic_type
                )
                assert non_passphrase_seed == data["seeds"]["Electrum-V2"][words][mnemonic_type][language]["non-passphrase-seed"]

                for passphrase in data["seeds"]["Electrum-V2"][words][mnemonic_type][language]["passphrases"].keys():
                    assert ElectrumV2Seed.from_mnemonic(
                        mnemonic=mnemonic,
                        passphrase=passphrase,
                        language=language,
                        mnemonic_type=mnemonic_type
                    ) == data["seeds"]["Electrum-V2"][words][mnemonic_type][language]["passphrases"][passphrase]
