#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ecdsa.ecdsa import generator_secp256k1

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import IEllipticCurveCryptography
from .point import (  # noqa: F401
    SLIP10Secp256k1Point, SLIP10Secp256k1PointCoincurve, SLIP10Secp256k1PointECDSA
)
from .public_key import (  # noqa: F401
    SLIP10Secp256k1PublicKey, SLIP10Secp256k1PublicKeyCoincurve, SLIP10Secp256k1PublicKeyECDSA
)
from .private_key import (  # noqa: F401
    SLIP10Secp256k1PrivateKey, SLIP10Secp256k1PrivateKeyCoincurve, SLIP10Secp256k1PrivateKeyECDSA
)


class SLIP10Secp256k1ECCCoincurve(IEllipticCurveCryptography):

    NAME = "SLIP10-Secp256k1"
    ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    GENERATOR = SLIP10Secp256k1PointCoincurve.from_coordinates(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    )
    POINT = SLIP10Secp256k1PointCoincurve
    PUBLIC_KEY = SLIP10Secp256k1PublicKeyCoincurve
    PRIVATE_KEY = SLIP10Secp256k1PrivateKeyCoincurve


class SLIP10Secp256k1ECCECDSA(IEllipticCurveCryptography):

    NAME = "SLIP10-Secp256k1"
    ORDER = generator_secp256k1.order()
    GENERATOR = SLIP10Secp256k1PointECDSA(generator_secp256k1)
    POINT = SLIP10Secp256k1PointECDSA
    PUBLIC_KEY = SLIP10Secp256k1PublicKeyECDSA
    PRIVATE_KEY = SLIP10Secp256k1PrivateKeyECDSA


if SLIP10_SECP256K1_CONST.USE == "coincurve":
    SLIP10Secp256k1ECC = SLIP10Secp256k1ECCCoincurve
elif SLIP10_SECP256K1_CONST.USE == "ecdsa":
    SLIP10Secp256k1ECC = SLIP10Secp256k1ECCECDSA
else:
    raise Exception(
        f"Invalid SLIP10-Secp256k1 use, (expected: 'coincurve' or 'ecdsa', got: '{SLIP10_SECP256K1_CONST.USE}')"
    )
