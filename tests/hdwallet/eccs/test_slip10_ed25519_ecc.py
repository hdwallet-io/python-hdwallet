#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from nacl.signing import (
    SigningKey, VerifyKey
)

from hdwallet.eccs import (
    IPoint, IPublicKey, IPrivateKey
)
from hdwallet.eccs.slip10.ed25519 import (
    SLIP10Ed25519ECC, SLIP10Ed25519Point, SLIP10Ed25519PublicKey, SLIP10Ed25519PrivateKey
)
from hdwallet.utils import get_bytes


def test_slip10_ed25519_ecc(data):

    assert SLIP10Ed25519ECC.NAME == data["eccs"]["SLIP10-Ed25519"]["name"]
    assert isinstance(SLIP10Ed25519ECC.ORDER, int)
    assert isinstance(SLIP10Ed25519ECC.GENERATOR, IPoint)
    assert isinstance(SLIP10Ed25519ECC.POINT, type(SLIP10Ed25519Point))
    assert isinstance(SLIP10Ed25519ECC.PUBLIC_KEY, type(SLIP10Ed25519PublicKey))
    assert isinstance(SLIP10Ed25519ECC.PRIVATE_KEY, type(SLIP10Ed25519PrivateKey))


def test_slip10_ed25519_ecc_point(data):

    assert SLIP10Ed25519Point.name() == data["eccs"]["SLIP10-Ed25519"]["name"]
    for public_key_type in ["uncompressed", "compressed"]:
        # Test from bytes
        point = SLIP10Ed25519Point.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["encode"])
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Ed25519Point)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["decode"])
        # Test from coordinate
        point = SLIP10Ed25519Point.from_coordinates(
            x=data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["x"],
            y=data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["y"]
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Ed25519Point)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["point"]["decode"])

        for number in range(2, 50):
            point_add, point_radd, point_mul, point_rmul = (
                point + (point * (number - 1)), (point * (number - 1)) + point, point * number, number * point
            )
            assert point_add.raw() == point_radd.raw() == point_mul.raw() == point_rmul.raw()
            assert point_add.raw_encoded() == point_radd.raw_encoded() == point_mul.raw_encoded() == point_rmul.raw_encoded()
            assert point_add.raw_decoded() == point_radd.raw_decoded() == point_mul.raw_decoded() == point_rmul.raw_decoded()
            assert point_add.x() == point_radd.x() == point_mul.x() == point_rmul.x()
            assert point_add.y() == point_radd.y() == point_mul.y() == point_rmul.y()


def test_slip10_ed25519_ecc_public_key(data):

    assert SLIP10Ed25519PublicKey.name() == data["eccs"]["SLIP10-Ed25519"]["name"]
    assert SLIP10Ed25519PublicKey.uncompressed_length() == data["eccs"]["SLIP10-Ed25519"]["uncompressed"]["length"]
    assert SLIP10Ed25519PublicKey.compressed_length() == data["eccs"]["SLIP10-Ed25519"]["compressed"]["length"]
    for public_key_type in ["uncompressed", "compressed"]:
        public_key = SLIP10Ed25519PublicKey.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Ed25519"][public_key_type]["public-key"])
        )
        assert isinstance(public_key, IPublicKey)
        assert isinstance(public_key, SLIP10Ed25519PublicKey)
        assert isinstance(public_key.underlying_object(), VerifyKey)
        assert public_key.raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Ed25519"]["uncompressed"]["public-key"])
        assert public_key.raw_compressed() == get_bytes(data["eccs"]["SLIP10-Ed25519"]["compressed"]["public-key"])
        assert isinstance(public_key.point(), IPoint)
        assert isinstance(public_key.point(), SLIP10Ed25519Point)


def test_slip10_ed25519_ecc_private_key(data):

    assert SLIP10Ed25519PrivateKey.name() == data["eccs"]["SLIP10-Ed25519"]["name"]
    assert SLIP10Ed25519PrivateKey.length() == data["eccs"]["SLIP10-Ed25519"]["private-key-length"]
    private_key = SLIP10Ed25519PrivateKey.from_bytes(
        get_bytes(data["eccs"]["SLIP10-Ed25519"]["private-key"])
    )
    assert isinstance(private_key, IPrivateKey)
    assert isinstance(private_key, SLIP10Ed25519PrivateKey)
    assert isinstance(private_key.underlying_object(), SigningKey)
    assert isinstance(private_key.raw(), bytes)
    assert private_key.raw() == get_bytes(data["eccs"]["SLIP10-Ed25519"]["private-key"])
    assert isinstance(private_key.public_key(), IPublicKey)
    assert isinstance(private_key.public_key(), SLIP10Ed25519PublicKey)
    assert private_key.public_key().raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Ed25519"]["uncompressed"]["public-key"])
    assert private_key.public_key().raw_compressed() == get_bytes(data["eccs"]["SLIP10-Ed25519"]["compressed"]["public-key"])
