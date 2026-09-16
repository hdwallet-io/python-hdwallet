#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.seeds.electrum.v1 import ElectrumV1Seed


def test_electrum_v1_seeds(data):
    assert ElectrumV1Seed.from_mnemonic(
        mnemonic=data["seeds"]["Electrum-V1"]["12"]["english"]["mnemonic"]
    ) == data["seeds"]["Electrum-V1"]["12"]["english"]["non-passphrase-seed"]

