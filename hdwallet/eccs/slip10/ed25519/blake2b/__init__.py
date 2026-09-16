#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ....iecc import IEllipticCurveCryptography
from .. import SLIP10Ed25519ECC
from .point import SLIP10Ed25519Blake2bPoint
from .public_key import SLIP10Ed25519Blake2bPublicKey
from .private_key import SLIP10Ed25519Blake2bPrivateKey


class SLIP10Ed25519Blake2bECC(IEllipticCurveCryptography):

    NAME = "SLIP10-Ed25519-Blake2b"
    ORDER = SLIP10Ed25519ECC.ORDER
    GENERATOR = SLIP10Ed25519ECC.GENERATOR
    POINT = SLIP10Ed25519Blake2bPoint
    PUBLIC_KEY = SLIP10Ed25519Blake2bPublicKey
    PRIVATE_KEY = SLIP10Ed25519Blake2bPrivateKey
