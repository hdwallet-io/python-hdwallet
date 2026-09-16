#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import pytest

from hdwallet.derivations.hdw import HDWDerivation
from hdwallet.exceptions import DerivationError


def test_hdw_derivation(data):

    derivation = HDWDerivation()
    assert derivation.name() == data["derivations"]["HDW"]["default"]["name"]
    assert derivation.account() == data["derivations"]["HDW"]["default"]["account"]
    assert derivation.ecc() == data["derivations"]["HDW"]["default"]["ecc"]
    assert derivation.address() == data["derivations"]["HDW"]["default"]["address"]
    assert derivation.path() == data["derivations"]["HDW"]["default"]["path"]

    derivation = HDWDerivation(
        account=data["derivations"]["HDW"]["from"]["account"],
        ecc=data["derivations"]["HDW"]["from"]["ecc"],
        address=data["derivations"]["HDW"]["from"]["address"]
    )
    assert derivation.account() == data["derivations"]["HDW"]["from"]["account"]
    assert derivation.ecc() == data["derivations"]["HDW"]["from"]["ecc"]
    assert derivation.address() == data["derivations"]["HDW"]["from"]["address"]
    assert derivation.path() == data["derivations"]["HDW"]["from"]["path"]

    derivation.clean()
    assert derivation.name() == data["derivations"]["HDW"]["default"]["name"]
    assert derivation.account() == data["derivations"]["HDW"]["default"]["account"]
    assert derivation.ecc() == data["derivations"]["HDW"]["from"]["ecc"]
    assert derivation.address() == data["derivations"]["HDW"]["default"]["address"]

    derivation = HDWDerivation()
    derivation.from_account(data["derivations"]["HDW"]["from"]["account"])
    derivation.from_ecc(data["derivations"]["HDW"]["from"]["ecc"])
    derivation.from_address(data["derivations"]["HDW"]["from"]["address"])
    assert derivation.account() == data["derivations"]["HDW"]["from"]["account"]
    assert derivation.ecc() == data["derivations"]["HDW"]["from"]["ecc"]
    assert derivation.address() == data["derivations"]["HDW"]["from"]["address"]
    assert derivation.path() == data["derivations"]["HDW"]["from"]["path"]

    with pytest.raises(DerivationError):
        HDWDerivation(ecc="invalid-ecc")

    with pytest.raises(DerivationError):
        derivation = HDWDerivation()
        derivation.from_ecc("invalid-ecc")
