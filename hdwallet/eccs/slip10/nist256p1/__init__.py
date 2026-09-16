#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ecdsa.ecdsa import generator_256

from ...iecc import IEllipticCurveCryptography
from .point import SLIP10Nist256p1Point
from .public_key import SLIP10Nist256p1PublicKey
from .private_key import SLIP10Nist256p1PrivateKey


class SLIP10Nist256p1ECC(IEllipticCurveCryptography):

    NAME = "SLIP10-Nist256p1"
    ORDER = generator_256.order()
    GENERATOR = SLIP10Nist256p1Point(generator_256)
    POINT = SLIP10Nist256p1Point
    PUBLIC_KEY = SLIP10Nist256p1PublicKey
    PRIVATE_KEY = SLIP10Nist256p1PrivateKey
