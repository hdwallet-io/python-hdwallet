#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.electrum import ElectrumDerivation
from hdwallet.exceptions import DerivationError


def test_electrum_derivation(data):

    derivation = ElectrumDerivation()
    assert derivation.name() == data["derivations"]["Electrum"]["default"]["name"]
    assert derivation.change() == data["derivations"]["Electrum"]["default"]["change"]
    assert derivation.address() == data["derivations"]["Electrum"]["default"]["address"]

    derivation = ElectrumDerivation(
        change=data["derivations"]["Electrum"]["from"]["change"],
        address=data["derivations"]["Electrum"]["from"]["address"]

    )
    assert derivation.change() == data["derivations"]["Electrum"]["from"]["change"]
    assert derivation.address() == data["derivations"]["Electrum"]["from"]["address"]

    derivation.clean()
    assert derivation.change() == data["derivations"]["Electrum"]["default"]["change"]
    assert derivation.address() == data["derivations"]["Electrum"]["default"]["address"]

    derivation = ElectrumDerivation()
    derivation.from_change(data["derivations"]["Electrum"]["from"]["change"])
    derivation.from_address(data["derivations"]["Electrum"]["from"]["address"])
    assert derivation.change() == data["derivations"]["Electrum"]["from"]["change"]
    assert derivation.address() == data["derivations"]["Electrum"]["from"]["address"]
