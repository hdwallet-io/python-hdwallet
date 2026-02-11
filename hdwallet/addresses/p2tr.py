#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.segwit_bech32 import (
    segwit_encode, segwit_decode
)
from ..eccs import (
    IPoint, IPublicKey, SLIP10Secp256k1ECC, SLIP10Secp256k1Point, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Bitcoin
from ..crypto import sha256
from ..utils import (
    get_bytes, integer_to_bytes, bytes_to_integer, bytes_to_string
)
from .iaddress import IAddress


class P2TRAddress(IAddress):

    hrp: str = Bitcoin.NETWORKS.MAINNET.HRP
    field_size: int = Bitcoin.PARAMS.FIELD_SIZE
    tap_tweak_sha256: bytes = get_bytes(Bitcoin.PARAMS.TAP_TWEAK_SHA256)
    witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "P2TR".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "P2TR"

    @classmethod
    def tagged_hash(cls, tag: Union[bytes, str], data_bytes: bytes) -> bytes:
        """
        Computes a tagged hash using a double SHA256 hash with the given tag and data.

        :param tag: The tag used for hashing, either as bytes or a string.
        :type tag: Union[bytes, str]
        :param data_bytes: The data bytes to be hashed.
        :type data_bytes: bytes

        :return: The double SHA256 tagged hash.
        :rtype: bytes
        """

        tag_hash = sha256(tag) if isinstance(tag, str) else tag
        return sha256(tag_hash + tag_hash + data_bytes)

    @classmethod
    def hash_tap_tweak(cls, pub_key: IPublicKey) -> bytes:
        """
        Computes a hash using a tagged hash with the tap tweak SHA256
        algorithm and the x-coordinate of the public key.

        :param pub_key: The public key for computing the tweak hash.
        :type pub_key: IPublicKey

        :return: The hashed tap tweak.
        :rtype: bytes
        """

        return cls.tagged_hash(cls.tap_tweak_sha256, integer_to_bytes(pub_key.point().x()))

    @classmethod
    def lift_x(cls, pub_key: IPublicKey) -> IPoint:
        """
        Lifts the x-coordinate of a given public key onto the secp256k1
        elliptic curve to compute its corresponding y-coordinate.

        :param pub_key: The public key whose x-coordinate needs to be lifted.
        :type pub_key: IPublicKey

        :return: The elliptic curve point (x, y) corresponding to the lifted x-coordinate.
        :rtype: IPoint
        """

        p = cls.field_size
        x = pub_key.point().x()
        if x >= p:
            raise ValueError("Unable to compute LiftX point")
        c = (pow(x, 3, p) + 7) % p
        y = pow(c, (p + 1) // 4, p)
        if c != pow(y, 2, p):
            raise ValueError("Unable to compute LiftX point")
        return SLIP10Secp256k1Point.from_coordinates(
            x, y if y % 2 == 0 else p - y
        )

    @classmethod
    def tweak_public_key(cls, pub_key: IPublicKey) -> bytes:
        """
        Tweaks a given public key by hashing its tap tweak and adjusting its x-coordinate on the secp256k1 elliptic curve.

        :param pub_key: The public key to be tweaked.
        :type pub_key: IPublicKey

        :return: The tweaked public key bytes.
        :rtype: bytes
        """
        h = cls.hash_tap_tweak(pub_key)
        out_point = cls.lift_x(pub_key) + (bytes_to_integer(h) * SLIP10Secp256k1ECC.GENERATOR)
        return integer_to_bytes(out_point.x())

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes a public key into a SegWit address format using specified human-readable part (HRP) and witness version.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
            - witness_version: SegWit witness version (optional).
        :type kwargs: Any

        :return: The encoded SegWit address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        return segwit_encode(
            kwargs.get("hrp", cls.hrp),
            kwargs.get("witness_version", cls.witness_version),
            cls.tweak_public_key(public_key)
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes a SegWit address into its original public key using the specified human-readable part (HRP).

        :param address: The SegWit address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        witness_version, address_decode = segwit_decode(
            kwargs.get("hrp", cls.hrp), address
        )

        expected_length: int = SLIP10Secp256k1PublicKey.compressed_length() - 1
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")
        if witness_version != cls.witness_version:
            raise ValueError(f"Invalid witness version (expected: {cls.witness_version}, got: {witness_version})")

        return bytes_to_string(address_decode)
