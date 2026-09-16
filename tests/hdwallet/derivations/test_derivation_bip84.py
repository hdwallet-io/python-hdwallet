#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.bip84 import BIP84Derivation
from hdwallet.exceptions import DerivationError


def test_bip84_derivation(data):

    derivation = BIP84Derivation()
    assert derivation.name() == data["derivations"]["BIP84"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP84"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP84"]["default"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP84"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP84"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP84"]["default"]["address"]
    assert derivation.path() == data["derivations"]["BIP84"]["default"]["path"]

    derivation = BIP84Derivation(
        coin_type=data["derivations"]["BIP84"]["from"]["coin_type"],
        account=data["derivations"]["BIP84"]["from"]["account"],
        change=data["derivations"]["BIP84"]["from"]["change"],
        address=data["derivations"]["BIP84"]["from"]["address"]
    )
    assert derivation.coin_type() == data["derivations"]["BIP84"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP84"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP84"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP84"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP84"]["from"]["path"]

    derivation.clean()
    assert derivation.name() == data["derivations"]["BIP84"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP84"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP84"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP84"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP84"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP84"]["default"]["address"]

    derivation = BIP84Derivation()
    derivation.from_coin_type(data["derivations"]["BIP84"]["from"]["coin_type"])
    derivation.from_account(data["derivations"]["BIP84"]["from"]["account"])
    derivation.from_change(data["derivations"]["BIP84"]["from"]["change"])
    derivation.from_address(data["derivations"]["BIP84"]["from"]["address"])
    assert derivation.coin_type() == data["derivations"]["BIP84"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP84"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP84"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP84"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP84"]["from"]["path"]

    with pytest.raises(DerivationError):
        BIP84Derivation(change="invalid-change")

    with pytest.raises(DerivationError):
        derivation = BIP84Derivation()
        derivation.from_change("invalid-change")
