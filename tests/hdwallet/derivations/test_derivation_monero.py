#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.derivations.monero import MoneroDerivation
from hdwallet.exceptions import DerivationError


def test_monero_derivation(data):

    derivation = MoneroDerivation()
    assert derivation.name() == data["derivations"]["Monero"]["default"]["name"]
    assert derivation.minor() == data["derivations"]["Monero"]["default"]["minor"]
    assert derivation.major() == data["derivations"]["Monero"]["default"]["major"]

    derivation = MoneroDerivation(
        minor=data["derivations"]["Monero"]["from"]["minor"],
        major=data["derivations"]["Monero"]["from"]["major"]

    )
    assert derivation.minor() == data["derivations"]["Monero"]["from"]["minor"]
    assert derivation.major() == data["derivations"]["Monero"]["from"]["major"]

    derivation.clean()
    assert derivation.minor() == data["derivations"]["Monero"]["default"]["minor"]
    assert derivation.major() == data["derivations"]["Monero"]["default"]["major"]

    derivation = MoneroDerivation()
    derivation.from_minor(data["derivations"]["Monero"]["from"]["minor"])
    derivation.from_major(data["derivations"]["Monero"]["from"]["major"])
    assert derivation.minor() == data["derivations"]["Monero"]["from"]["minor"]
    assert derivation.major() == data["derivations"]["Monero"]["from"]["major"]
