#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ....iecc import IEllipticCurveCryptography
from .. import SLIP10Ed25519ECC
from .point import SLIP10Ed25519MoneroPoint
from .public_key import SLIP10Ed25519MoneroPublicKey
from .private_key import SLIP10Ed25519MoneroPrivateKey


class SLIP10Ed25519MoneroECC(IEllipticCurveCryptography):

    NAME = "SLIP10-Ed25519-Monero"
    ORDER = SLIP10Ed25519ECC.ORDER
    GENERATOR = SLIP10Ed25519ECC.GENERATOR
    POINT = SLIP10Ed25519MoneroPoint
    PUBLIC_KEY = SLIP10Ed25519MoneroPublicKey
    PRIVATE_KEY = SLIP10Ed25519MoneroPrivateKey
