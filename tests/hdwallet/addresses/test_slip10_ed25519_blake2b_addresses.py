#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.addresses.nano import NanoAddress


def test_nano_address(data):

    assert NanoAddress.name() == data["addresses"]["SLIP10-Ed25519-Blake2b"]["addresses"]["Nano"]["name"]
    assert NanoAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519-Blake2b"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519-Blake2b"]["addresses"]["Nano"]["encode"]

    assert NanoAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519-Blake2b"]["addresses"]["Nano"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519-Blake2b"]["addresses"]["Nano"]["decode"]

