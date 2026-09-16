#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ecdsa import (
    SigningKey, VerifyingKey
)
from ecdsa.ellipticcurve import PointJacobi
from coincurve import (
    PrivateKey, PublicKey
)

from hdwallet.eccs import (
    IPoint, IPublicKey, IPrivateKey
)
from hdwallet.eccs.slip10.secp256k1 import SLIP10Secp256k1ECC

from hdwallet.eccs.slip10.secp256k1.point import (
    SLIP10Secp256k1PointECDSA, SLIP10Secp256k1PointCoincurve
)
from hdwallet.eccs.slip10.secp256k1.public_key import (
    SLIP10Secp256k1PublicKeyECDSA, SLIP10Secp256k1PublicKeyCoincurve
)
from hdwallet.eccs.slip10.secp256k1.private_key import (
    SLIP10Secp256k1PrivateKeyECDSA, SLIP10Secp256k1PrivateKeyCoincurve
)

from hdwallet.utils import get_bytes


def test_slip10_secp256k1_ecc_coincurve(data):

    assert SLIP10Secp256k1ECC.NAME == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert isinstance(SLIP10Secp256k1ECC.ORDER, int)
    assert isinstance(SLIP10Secp256k1ECC.GENERATOR, IPoint)
    assert isinstance(SLIP10Secp256k1ECC.POINT, type(SLIP10Secp256k1PointCoincurve))
    assert isinstance(SLIP10Secp256k1ECC.PUBLIC_KEY, type(SLIP10Secp256k1PublicKeyCoincurve))
    assert isinstance(SLIP10Secp256k1ECC.PRIVATE_KEY, type(SLIP10Secp256k1PrivateKeyCoincurve))


def test_slip10_secp256k1_ecc_point_coincurve(data):

    assert SLIP10Secp256k1PointCoincurve.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    for public_key_type in ["uncompressed", "compressed"]:
        # Test from bytes
        point = SLIP10Secp256k1PointCoincurve.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Secp256k1PointCoincurve)
        assert isinstance(point.underlying_object(), PublicKey)
        assert point.x() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["decode"])
        # Test from coordinate
        point = SLIP10Secp256k1PointCoincurve.from_coordinates(
            x=data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"],
            y=data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Secp256k1PointCoincurve)
        assert isinstance(point.underlying_object(), PublicKey)
        assert point.x() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["decode"])

        for number in range(2, 50):
            point_add, point_radd, point_mul, point_rmul = (
                point + (point * (number - 1)), (point * (number - 1)) + point, point * number, number * point
            )
            assert point_add.raw() == point_radd.raw() == point_mul.raw() == point_rmul.raw()
            assert point_add.raw_encoded() == point_radd.raw_encoded() == point_mul.raw_encoded() == point_rmul.raw_encoded()
            assert point_add.raw_decoded() == point_radd.raw_decoded() == point_mul.raw_decoded() == point_rmul.raw_decoded()
            assert point_add.x() == point_radd.x() == point_mul.x() == point_rmul.x()
            assert point_add.y() == point_radd.y() == point_mul.y() == point_rmul.y()


def test_slip10_secp256k1_ecc_public_key_coincurve(data):

    assert SLIP10Secp256k1PublicKeyCoincurve.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert SLIP10Secp256k1PublicKeyCoincurve.uncompressed_length() == data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["length"]
    assert SLIP10Secp256k1PublicKeyCoincurve.compressed_length() == data["eccs"]["SLIP10-Secp256k1"]["compressed"]["length"]
    for public_key_type in ["uncompressed", "compressed"]:
        public_key = SLIP10Secp256k1PublicKeyCoincurve.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["public-key"])
        )
        assert isinstance(public_key, IPublicKey)
        assert isinstance(public_key, SLIP10Secp256k1PublicKeyCoincurve)
        assert isinstance(public_key.underlying_object(), PublicKey)
        assert public_key.raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["public-key"])
        assert public_key.raw_compressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["compressed"]["public-key"])
        assert isinstance(public_key.point(), IPoint)
        assert isinstance(public_key.point(), SLIP10Secp256k1PointCoincurve)


def test_slip10_secp256k1_ecc_private_key_coincurve(data):

    assert SLIP10Secp256k1PrivateKeyCoincurve.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert SLIP10Secp256k1PrivateKeyCoincurve.length() == data["eccs"]["SLIP10-Secp256k1"]["private-key-length"]
    private_key = SLIP10Secp256k1PrivateKeyCoincurve.from_bytes(
        get_bytes(data["eccs"]["SLIP10-Secp256k1"]["private-key"])
    )
    assert isinstance(private_key, IPrivateKey)
    assert isinstance(private_key, SLIP10Secp256k1PrivateKeyCoincurve)
    assert isinstance(private_key.underlying_object(), PrivateKey)
    assert isinstance(private_key.raw(), bytes)
    assert private_key.raw() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["private-key"])
    assert isinstance(private_key.public_key(), IPublicKey)
    assert isinstance(private_key.public_key(), SLIP10Secp256k1PublicKeyCoincurve)
    assert private_key.public_key().raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["public-key"])
    assert private_key.public_key().raw_compressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["compressed"]["public-key"])


def test_slip10_secp256k1_ecc_ecdsa(data):

    assert SLIP10Secp256k1ECC.NAME == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert isinstance(SLIP10Secp256k1ECC.ORDER, int)
    assert isinstance(SLIP10Secp256k1ECC.GENERATOR, IPoint)
    assert isinstance(SLIP10Secp256k1ECC.POINT, type(SLIP10Secp256k1PointECDSA))
    assert isinstance(SLIP10Secp256k1ECC.PUBLIC_KEY, type(SLIP10Secp256k1PublicKeyECDSA))
    assert isinstance(SLIP10Secp256k1ECC.PRIVATE_KEY, type(SLIP10Secp256k1PrivateKeyECDSA))


def test_slip10_secp256k1_ecc_point_ecdsa(data):

    assert SLIP10Secp256k1PointECDSA.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    for public_key_type in ["uncompressed", "compressed"]:
        # Test from bytes
        point = SLIP10Secp256k1PointECDSA.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Secp256k1PointECDSA)
        assert isinstance(point.underlying_object(), PointJacobi)
        assert point.x() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["decode"])
        # Test from coordinate
        point = SLIP10Secp256k1PointECDSA.from_coordinates(
            x=data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"],
            y=data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Secp256k1PointECDSA)
        assert isinstance(point.underlying_object(), PointJacobi)
        assert point.x() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["point"]["decode"])

        for number in range(2, 50):
            point_add, point_radd, point_mul, point_rmul = (
                point + (point * (number - 1)), (point * (number - 1)) + point, point * number, number * point
            )
            assert point_add.raw() == point_radd.raw() == point_mul.raw() == point_rmul.raw()
            assert point_add.raw_encoded() == point_radd.raw_encoded() == point_mul.raw_encoded() == point_rmul.raw_encoded()
            assert point_add.raw_decoded() == point_radd.raw_decoded() == point_mul.raw_decoded() == point_rmul.raw_decoded()
            assert point_add.x() == point_radd.x() == point_mul.x() == point_rmul.x()
            assert point_add.y() == point_radd.y() == point_mul.y() == point_rmul.y()


def test_slip10_secp256k1_ecc_public_key_ecdsa(data):

    assert SLIP10Secp256k1PublicKeyECDSA.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert SLIP10Secp256k1PublicKeyECDSA.uncompressed_length() == data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["length"]
    assert SLIP10Secp256k1PublicKeyECDSA.compressed_length() == data["eccs"]["SLIP10-Secp256k1"]["compressed"]["length"]
    for public_key_type in ["uncompressed", "compressed"]:
        public_key = SLIP10Secp256k1PublicKeyECDSA.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Secp256k1"][public_key_type]["public-key"])
        )
        assert isinstance(public_key, IPublicKey)
        assert isinstance(public_key, SLIP10Secp256k1PublicKeyECDSA)
        assert isinstance(public_key.underlying_object(), VerifyingKey)
        assert public_key.raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["public-key"])
        assert public_key.raw_compressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["compressed"]["public-key"])
        assert isinstance(public_key.point(), IPoint)
        assert isinstance(public_key.point(), SLIP10Secp256k1PointECDSA)


def test_slip10_secp256k1_ecc_private_key(data):

    assert SLIP10Secp256k1PrivateKeyECDSA.name() == data["eccs"]["SLIP10-Secp256k1"]["name"]
    assert SLIP10Secp256k1PrivateKeyECDSA.length() == data["eccs"]["SLIP10-Secp256k1"]["private-key-length"]
    private_key = SLIP10Secp256k1PrivateKeyECDSA.from_bytes(
        get_bytes(data["eccs"]["SLIP10-Secp256k1"]["private-key"])
    )
    assert isinstance(private_key, IPrivateKey)
    assert isinstance(private_key, SLIP10Secp256k1PrivateKeyECDSA)
    assert isinstance(private_key.underlying_object(), SigningKey)
    assert isinstance(private_key.raw(), bytes)
    assert private_key.raw() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["private-key"])
    assert isinstance(private_key.public_key(), IPublicKey)
    assert isinstance(private_key.public_key(), SLIP10Secp256k1PublicKeyECDSA)
    assert private_key.public_key().raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["uncompressed"]["public-key"])
    assert private_key.public_key().raw_compressed() == get_bytes(data["eccs"]["SLIP10-Secp256k1"]["compressed"]["public-key"])
