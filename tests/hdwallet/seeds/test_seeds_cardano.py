#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.cardano import CardanoSeed


def test_cardano_seeds(data):
    
    for words in data["seeds"]["Cardano"].keys():
        for cardano_type in data["seeds"]["Cardano"][words].keys():

            for lang in data["seeds"]["Cardano"][words][cardano_type].keys():
                assert CardanoSeed.from_mnemonic(
                    mnemonic=data["seeds"]["Cardano"][words][cardano_type][lang]["mnemonic"], cardano_type=cardano_type
                ) == data["seeds"]["Cardano"][words][cardano_type][lang]["non-passphrase-seed"]

                if data["seeds"]["Cardano"][words][cardano_type][lang]["passphrases"] == None:
                    continue

                for passphrase in data["seeds"]["Cardano"][words][cardano_type][lang]["passphrases"].keys():
                    assert CardanoSeed.from_mnemonic(
                        mnemonic= data["seeds"]["Cardano"][words][cardano_type][lang]["mnemonic"], 
                        passphrase=passphrase,
                        cardano_type=cardano_type
                    ) == data["seeds"]["Cardano"][words][cardano_type][lang]["passphrases"][passphrase]
