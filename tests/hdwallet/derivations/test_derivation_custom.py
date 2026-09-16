#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.custom import CustomDerivation
from hdwallet.exceptions import DerivationError


def test_custom_derivation(data):

    assert CustomDerivation().name() == data["derivations"]["Custom"]["name"]
    assert CustomDerivation().path() == data["derivations"]["Custom"]["default-path"]
    
    derivation = CustomDerivation().from_path(
        path=data["derivations"]["Custom"]["from-path"]["path"]
    )
    assert derivation.path() == data["derivations"]["Custom"]["from-path"]["path"]
    derivation.clean()
    assert derivation.path() == data["derivations"]["Custom"]["default-path"]

    assert CustomDerivation().from_indexes(
        indexes=data["derivations"]["Custom"]["from-path"]["indexes"]
    ).path() == data["derivations"]["Custom"]["from-path"]["path"]

    assert CustomDerivation().from_index(
        index=data["derivations"]["Custom"]["from-index"]["index"],
        hardened=data["derivations"]["Custom"]["from-index"]["hardened"]
    ).path() == data["derivations"]["Custom"]["from-index"]["path"]

    with pytest.raises(DerivationError, match="Bad path instance"):
        CustomDerivation().from_path(path={'FAKE_DICT'})

    with pytest.raises(DerivationError, match="Bad path format"):
        CustomDerivation().from_path(path='n/15/0/0/0/0')

    with pytest.raises(DerivationError, match="Bad indexes instance"):
        CustomDerivation().from_indexes(indexes={'FAKE_DICT'})

    with pytest.raises(DerivationError, match="Bad index instance"):
        CustomDerivation().from_index(index={'FAKE_DICT'})
