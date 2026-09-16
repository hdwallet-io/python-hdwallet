#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ...iecc import IEllipticCurveCryptography
from .point import SLIP10Ed25519Point
from .public_key import SLIP10Ed25519PublicKey
from .private_key import SLIP10Ed25519PrivateKey


class SLIP10Ed25519ECC(IEllipticCurveCryptography):

    NAME = "SLIP10-Ed25519"
    ORDER = 2 ** 252 + 27742317777372353535851937790883648493
    GENERATOR = SLIP10Ed25519Point.from_coordinates(
        15112221349535400772501151409588531511454012693041857206046113283949847762202,
        46316835694926478169428394003475163141307993866256225615783033603165251855960
    )
    POINT = SLIP10Ed25519Point
    PUBLIC_KEY = SLIP10Ed25519PublicKey
    PRIVATE_KEY = SLIP10Ed25519PrivateKey
