#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.addresses.neo import NeoAddress


def test_neo_address(data):

    assert NeoAddress.name() == data["addresses"]["SLIP10-Nist256p1"]["addresses"]["Neo"]["name"]
    assert NeoAddress.encode(
        public_key=data["addresses"]["SLIP10-Nist256p1"]["public-key"]
    ) == data["addresses"]["SLIP10-Nist256p1"]["addresses"]["Neo"]["encode"]

    assert NeoAddress.decode(
        address=data["addresses"]["SLIP10-Nist256p1"]["addresses"]["Neo"]["encode"]
    ) == data["addresses"]["SLIP10-Nist256p1"]["addresses"]["Neo"]["decode"]

