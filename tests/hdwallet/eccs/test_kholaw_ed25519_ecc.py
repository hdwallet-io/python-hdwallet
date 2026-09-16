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
from hdwallet.eccs.kholaw.ed25519 import (
    KholawEd25519ECC, KholawEd25519Point, KholawEd25519PublicKey, KholawEd25519PrivateKey
)
from hdwallet.utils import get_bytes


def test_kholaw_ed25519_ecc(data):

    assert KholawEd25519ECC.NAME == data["eccs"]["Kholaw-Ed25519"]["name"]
    assert isinstance(KholawEd25519ECC.ORDER, int)
    assert isinstance(KholawEd25519ECC.GENERATOR, IPoint)
    assert isinstance(KholawEd25519ECC.POINT, type(KholawEd25519Point))
    assert isinstance(KholawEd25519ECC.PUBLIC_KEY, type(KholawEd25519PublicKey))
    assert isinstance(KholawEd25519ECC.PRIVATE_KEY, type(KholawEd25519PrivateKey))


def test_kholaw_ed25519_ecc_point(data):

    assert KholawEd25519Point.name() == data["eccs"]["Kholaw-Ed25519"]["name"]
    for public_key_type in ["uncompressed", "compressed"]:
        # Test from bytes
        point = KholawEd25519Point.from_bytes(
            get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["encode"])
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, KholawEd25519Point)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["decode"])
        # Test from coordinate
        point = KholawEd25519Point.from_coordinates(
            x=data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["x"],
            y=data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["y"]
        )
        assert isinstance(point, IPoint)
        assert isinstance(point, KholawEd25519Point)
        assert isinstance(point.underlying_object(), bytes)
        assert point.x() == data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["x"]
        assert point.y() == data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["y"]
        assert point.raw() == point.raw_encoded() == get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["encode"])
        assert point.raw_decoded() == get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["point"]["decode"])

        for number in range(2, 50):
            point_add, point_radd, point_mul, point_rmul = (
                point + (point * (number - 1)), (point * (number - 1)) + point, point * number, number * point
            )
            assert point_add.raw() == point_radd.raw() == point_mul.raw() == point_rmul.raw()
            assert point_add.raw_encoded() == point_radd.raw_encoded() == point_mul.raw_encoded() == point_rmul.raw_encoded()
            assert point_add.raw_decoded() == point_radd.raw_decoded() == point_mul.raw_decoded() == point_rmul.raw_decoded()
            assert point_add.x() == point_radd.x() == point_mul.x() == point_rmul.x()
            assert point_add.y() == point_radd.y() == point_mul.y() == point_rmul.y()


def test_kholaw_ed25519_ecc_public_key(data):

    assert KholawEd25519PublicKey.name() == data["eccs"]["Kholaw-Ed25519"]["name"]
    assert KholawEd25519PublicKey.uncompressed_length() == data["eccs"]["Kholaw-Ed25519"]["uncompressed"]["length"]
    assert KholawEd25519PublicKey.compressed_length() == data["eccs"]["Kholaw-Ed25519"]["compressed"]["length"]
    for public_key_type in ["uncompressed", "compressed"]:
        public_key = KholawEd25519PublicKey.from_bytes(
            get_bytes(data["eccs"]["Kholaw-Ed25519"][public_key_type]["public-key"])
        )
        assert isinstance(public_key, IPublicKey)
        assert isinstance(public_key, KholawEd25519PublicKey)
        assert isinstance(public_key.underlying_object(), VerifyKey)
        assert public_key.raw_uncompressed() == get_bytes(data["eccs"]["Kholaw-Ed25519"]["uncompressed"]["public-key"])
        assert public_key.raw_compressed() == get_bytes(data["eccs"]["Kholaw-Ed25519"]["compressed"]["public-key"])
        assert isinstance(public_key.point(), IPoint)
        assert isinstance(public_key.point(), KholawEd25519Point)


def test_kholaw_ed25519_ecc_private_key(data):

    assert KholawEd25519PrivateKey.name() == data["eccs"]["Kholaw-Ed25519"]["name"]
    assert KholawEd25519PrivateKey.length() == data["eccs"]["Kholaw-Ed25519"]["private-key-length"]
    private_key = KholawEd25519PrivateKey.from_bytes(
        get_bytes(data["eccs"]["Kholaw-Ed25519"]["private-key"])
    )
    assert isinstance(private_key, IPrivateKey)
    assert isinstance(private_key, KholawEd25519PrivateKey)
    assert isinstance(private_key.underlying_object(), SigningKey)
    assert isinstance(private_key.raw(), bytes)
    assert private_key.raw() == get_bytes(data["eccs"]["Kholaw-Ed25519"]["private-key"])
    assert isinstance(private_key.public_key(), IPublicKey)
    assert isinstance(private_key.public_key(), KholawEd25519PublicKey)
    assert private_key.public_key().raw_uncompressed() == get_bytes(data["eccs"]["Kholaw-Ed25519"]["uncompressed"]["public-key"])
    assert private_key.public_key().raw_compressed() == get_bytes(data["eccs"]["Kholaw-Ed25519"]["compressed"]["public-key"])
