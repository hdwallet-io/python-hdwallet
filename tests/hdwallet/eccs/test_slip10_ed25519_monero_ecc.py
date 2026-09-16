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
from hdwallet.eccs.slip10.ed25519.monero import (
    SLIP10Ed25519MoneroECC, SLIP10Ed25519MoneroPoint, SLIP10Ed25519MoneroPublicKey, SLIP10Ed25519MoneroPrivateKey
)
from hdwallet.utils import get_bytes


def test_slip10_ed25519_monero_ecc(data):

    assert SLIP10Ed25519MoneroECC.NAME == data["eccs"]["SLIP10-Ed25519-Monero"]["name"]
    assert isinstance(SLIP10Ed25519MoneroECC.ORDER, int)
    assert isinstance(SLIP10Ed25519MoneroECC.GENERATOR, IPoint)
    assert isinstance(SLIP10Ed25519MoneroECC.POINT, type(SLIP10Ed25519MoneroPoint))
    assert isinstance(SLIP10Ed25519MoneroECC.PUBLIC_KEY, type(SLIP10Ed25519MoneroPublicKey))
    assert isinstance(SLIP10Ed25519MoneroECC.PRIVATE_KEY, type(SLIP10Ed25519MoneroPrivateKey))


def test_slip10_ed25519_monero_ecc_point(data):

    assert SLIP10Ed25519MoneroPoint.name() == data["eccs"]["SLIP10-Ed25519-Monero"]["name"]
    for public_key_type in ["uncompressed", "compressed"]:
        # Test from bytes
        point = SLIP10Ed25519MoneroPoint.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["encode"])
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Ed25519MoneroPoint)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["decode"])
        # Test from coordinate
        point = SLIP10Ed25519MoneroPoint.from_coordinates(
            x=data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["x"],
            y=data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["y"]
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, SLIP10Ed25519MoneroPoint)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["point"]["decode"])

        for number in range(2, 50):
            point_add, point_radd, point_mul, point_rmul = (
                point + (point * (number - 1)), (point * (number - 1)) + point, point * number, number * point
            )
            assert point_add.raw() == point_radd.raw() == point_mul.raw() == point_rmul.raw()
            assert point_add.raw_encoded() == point_radd.raw_encoded() == point_mul.raw_encoded() == point_rmul.raw_encoded()
            assert point_add.raw_decoded() == point_radd.raw_decoded() == point_mul.raw_decoded() == point_rmul.raw_decoded()
            assert point_add.x() == point_radd.x() == point_mul.x() == point_rmul.x()
            assert point_add.y() == point_radd.y() == point_mul.y() == point_rmul.y()


def test_slip10_ed25519_monero_ecc_public_key(data):

    assert SLIP10Ed25519MoneroPublicKey.name() == data["eccs"]["SLIP10-Ed25519-Monero"]["name"]
    assert SLIP10Ed25519MoneroPublicKey.uncompressed_length() == data["eccs"]["SLIP10-Ed25519-Monero"]["uncompressed"]["length"]
    assert SLIP10Ed25519MoneroPublicKey.compressed_length() == data["eccs"]["SLIP10-Ed25519-Monero"]["compressed"]["length"]
    for public_key_type in ["uncompressed", "compressed"]:
        public_key = SLIP10Ed25519MoneroPublicKey.from_bytes(
            get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"][public_key_type]["public-key"])
        )
        assert isinstance(public_key, IPublicKey)
        assert isinstance(public_key, SLIP10Ed25519MoneroPublicKey)
        assert isinstance(public_key.underlying_object(), VerifyKey)
        assert public_key.raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["uncompressed"]["public-key"])
        assert public_key.raw_compressed() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["compressed"]["public-key"])
        assert isinstance(public_key.point(), IPoint)
        assert isinstance(public_key.point(), SLIP10Ed25519MoneroPoint)


def test_slip10_ed25519_monero_ecc_private_key(data):

    assert SLIP10Ed25519MoneroPrivateKey.name() == data["eccs"]["SLIP10-Ed25519-Monero"]["name"]
    assert SLIP10Ed25519MoneroPrivateKey.length() == data["eccs"]["SLIP10-Ed25519-Monero"]["private-key-length"]
    private_key = SLIP10Ed25519MoneroPrivateKey.from_bytes(
        get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["private-key"])
    )
    assert isinstance(private_key, IPrivateKey)
    assert isinstance(private_key, SLIP10Ed25519MoneroPrivateKey)
    assert isinstance(private_key.underlying_object(), SigningKey)
    assert isinstance(private_key.raw(), bytes)
    assert private_key.raw() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["private-key"])
    assert isinstance(private_key.public_key(), IPublicKey)
    assert isinstance(private_key.public_key(), SLIP10Ed25519MoneroPublicKey)
    assert private_key.public_key().raw_uncompressed() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["uncompressed"]["public-key"])
    assert private_key.public_key().raw_compressed() == get_bytes(data["eccs"]["SLIP10-Ed25519-Monero"]["compressed"]["public-key"])
