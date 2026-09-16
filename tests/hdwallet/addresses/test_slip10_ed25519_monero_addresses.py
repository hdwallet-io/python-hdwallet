#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.addresses.monero import MoneroAddress


def test_monero_address(data):

    assert MoneroAddress.name() == data["addresses"]["SLIP10-Ed25519-Monero"]["name"]
    assert MoneroAddress.encode(
        spend_public_key=data["addresses"]["SLIP10-Ed25519-Monero"]["spend-public-key"],
        view_public_key=data["addresses"]["SLIP10-Ed25519-Monero"]["view-public-key"],
        payment_id=data["addresses"]["SLIP10-Ed25519-Monero"]["args"]["payment_id"]
    ) == data["addresses"]["SLIP10-Ed25519-Monero"]["encode"]

    spend_public_key, view_public_key = MoneroAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519-Monero"]["encode"],
        payment_id=data["addresses"]["SLIP10-Ed25519-Monero"]["args"]["payment_id"]
    )
    assert spend_public_key == data["addresses"]["SLIP10-Ed25519-Monero"]["spend-public-key"]
    assert view_public_key == data["addresses"]["SLIP10-Ed25519-Monero"]["view-public-key"]
