#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.bip44 import (
    BIP44Derivation, CHANGES
)
from hdwallet.exceptions import DerivationError


def test_bip44_derivation(data):

    assert CHANGES.EXTERNAL_CHAIN == "external-chain"
    assert CHANGES.INTERNAL_CHAIN == "internal-chain"

    derivation = BIP44Derivation()
    assert derivation.name() == data["derivations"]["BIP44"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP44"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP44"]["default"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP44"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP44"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP44"]["default"]["address"]
    assert derivation.path() == data["derivations"]["BIP44"]["default"]["path"]

    derivation = BIP44Derivation(
        coin_type=data["derivations"]["BIP44"]["from"]["coin_type"],
        account=data["derivations"]["BIP44"]["from"]["account"],
        change=data["derivations"]["BIP44"]["from"]["change"],
        address=data["derivations"]["BIP44"]["from"]["address"]
    )
    assert derivation.coin_type() == data["derivations"]["BIP44"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP44"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP44"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP44"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP44"]["from"]["path"]

    derivation.clean()
    assert derivation.name() == data["derivations"]["BIP44"]["default"]["name"]
    assert derivation.purpose() == data["derivations"]["BIP44"]["default"]["purpose"]
    assert derivation.coin_type() == data["derivations"]["BIP44"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP44"]["default"]["account"]
    assert derivation.change() == data["derivations"]["BIP44"]["default"]["change"]
    assert derivation.address() == data["derivations"]["BIP44"]["default"]["address"]

    derivation = BIP44Derivation()
    derivation.from_coin_type(data["derivations"]["BIP44"]["from"]["coin_type"])
    derivation.from_account(data["derivations"]["BIP44"]["from"]["account"])
    derivation.from_change(data["derivations"]["BIP44"]["from"]["change"])
    derivation.from_address(data["derivations"]["BIP44"]["from"]["address"])
    assert derivation.coin_type() == data["derivations"]["BIP44"]["from"]["coin_type"]
    assert derivation.account() == data["derivations"]["BIP44"]["from"]["account"]
    assert derivation.change() == data["derivations"]["BIP44"]["from"]["change"]
    assert derivation.address() == data["derivations"]["BIP44"]["from"]["address"]
    assert derivation.path() == data["derivations"]["BIP44"]["from"]["path"]

    with pytest.raises(DerivationError):
        BIP44Derivation(change="invalid-change")

    with pytest.raises(DerivationError):
        derivation = BIP44Derivation()
        derivation.from_change("invalid-change")
