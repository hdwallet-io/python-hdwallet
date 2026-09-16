#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.bip86 import BIP86Derivation
from hdwallet.exceptions import DerivationError


def test_bip86_derivation(data):

    derivation = BIP86Derivation()
    assert derivation.name() == data["derivations"]["BIP86"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP86"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP86"]["default"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP86"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP86"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP86"]["default"]["address"]
    assert derivation.path() == data["derivations"]["BIP86"]["default"]["path"]

    derivation = BIP86Derivation(
        coin_type=data["derivations"]["BIP86"]["from"]["coin_type"],
        account=data["derivations"]["BIP86"]["from"]["account"],
        change=data["derivations"]["BIP86"]["from"]["change"],
        address=data["derivations"]["BIP86"]["from"]["address"]
    )
    assert derivation.coin_type() == data["derivations"]["BIP86"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP86"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP86"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP86"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP86"]["from"]["path"]

    derivation.clean()
    assert derivation.name() == data["derivations"]["BIP86"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP86"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP86"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP86"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP86"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP86"]["default"]["address"]

    derivation = BIP86Derivation()
    derivation.from_coin_type(data["derivations"]["BIP86"]["from"]["coin_type"])
    derivation.from_account(data["derivations"]["BIP86"]["from"]["account"])
    derivation.from_change(data["derivations"]["BIP86"]["from"]["change"])
    derivation.from_address(data["derivations"]["BIP86"]["from"]["address"])
    assert derivation.coin_type() == data["derivations"]["BIP86"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP86"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP86"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP86"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP86"]["from"]["path"]

    with pytest.raises(DerivationError):
        BIP86Derivation(change="invalid-change")

    with pytest.raises(DerivationError):
        derivation = BIP86Derivation()
        derivation.from_change("invalid-change")
