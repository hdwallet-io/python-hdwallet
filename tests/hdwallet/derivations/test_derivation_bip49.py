#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.bip49 import BIP49Derivation
from hdwallet.exceptions import DerivationError


def test_bip49_derivation(data):

    derivation = BIP49Derivation()
    assert derivation.name() == data["derivations"]["BIP49"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP49"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP49"]["default"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP49"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP49"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP49"]["default"]["address"]
    assert derivation.path() == data["derivations"]["BIP49"]["default"]["path"]

    derivation = BIP49Derivation(
        coin_type=data["derivations"]["BIP49"]["from"]["coin_type"],
        account=data["derivations"]["BIP49"]["from"]["account"],
        change=data["derivations"]["BIP49"]["from"]["change"],
        address=data["derivations"]["BIP49"]["from"]["address"]
    )
    assert derivation.coin_type() == data["derivations"]["BIP49"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP49"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP49"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP49"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP49"]["from"]["path"]

    derivation.clean()
    assert derivation.name() == data["derivations"]["BIP49"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP49"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP49"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP49"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP49"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP49"]["default"]["address"]

    derivation = BIP49Derivation()
    derivation.from_coin_type(data["derivations"]["BIP49"]["from"]["coin_type"])
    derivation.from_account(data["derivations"]["BIP49"]["from"]["account"])
    derivation.from_change(data["derivations"]["BIP49"]["from"]["change"])
    derivation.from_address(data["derivations"]["BIP49"]["from"]["address"])
    assert derivation.coin_type() == data["derivations"]["BIP49"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP49"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP49"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP49"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP49"]["from"]["path"]

    with pytest.raises(DerivationError):
        BIP49Derivation(change="invalid-change")

    with pytest.raises(DerivationError):
        derivation = BIP49Derivation()
        derivation.from_change("invalid-change")
