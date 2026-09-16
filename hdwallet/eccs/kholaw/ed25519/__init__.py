#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ...iecc import IEllipticCurveCryptography
from ...slip10.ed25519 import SLIP10Ed25519ECC
from .point import KholawEd25519Point
from .public_key import KholawEd25519PublicKey
from .private_key import KholawEd25519PrivateKey


class KholawEd25519ECC(IEllipticCurveCryptography):

    NAME = "Kholaw-Ed25519"
    ORDER = SLIP10Ed25519ECC.ORDER
    GENERATOR = SLIP10Ed25519ECC.GENERATOR
    POINT = KholawEd25519Point
    PUBLIC_KEY = KholawEd25519PublicKey
    PRIVATE_KEY = KholawEd25519PrivateKey
