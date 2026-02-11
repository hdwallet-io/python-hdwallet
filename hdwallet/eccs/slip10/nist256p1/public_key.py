#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa import VerifyingKey
from ecdsa.ecdsa import curve_256
from ecdsa import (
    curves, ellipticcurve, keys
)

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import (
    IPoint, IPublicKey
)
from .point import SLIP10Nist256p1Point


class SLIP10Nist256p1PublicKey(IPublicKey):

    verify_key: VerifyingKey

    def __init__(self, verify_key: VerifyingKey) -> None:
        """
        Initialize the public key with the given verifying key.

        :param verify_key: The verifying key used for initializing the public key.
        :type verify_key: VerifyingKey
        """

        self.verify_key = verify_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Nist256p1"

    @classmethod
    def from_bytes(cls, public_key: bytes) -> IPublicKey:
        """
        Create a public key instance from the given byte representation.

        :param public_key: The byte representation of the public key.
        :type public_key: bytes

        :return: An instance of IPublicKey.
        :rtype: IPublicKey
        """

        try:
            return cls(
                VerifyingKey.from_string(
                    public_key, curve=curves.NIST256p
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def from_point(cls, point: IPoint) -> IPublicKey:
        """
        Create a public key instance from a given point.

        :param point: The elliptic curve point representing the public key.
        :type point: IPoint

        :return: An instance of IPublicKey.
        :rtype: IPublicKey
        """

        try:
            return cls(
                VerifyingKey.from_public_point(
                    ellipticcurve.Point(
                        curve_256, point.x(), point.y()
                    ),
                    curve=curves.NIST256p
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key point") from ex

    @staticmethod
    def compressed_length() -> int:
        """
        Get the length of the compressed public key in bytes.

        :return: The length of the compressed public key.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_COMPRESSED_BYTE_LENGTH

    @staticmethod
    def uncompressed_length() -> int:
        """
        Get the length of the uncompressed public key in bytes.

        :return: The length of the uncompressed public key.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Get the underlying object of the public key.

        :return: The underlying object representing the public key.
        :rtype: Any
        """

        return self.verify_key

    def raw_compressed(self) -> bytes:
        """
        Get the compressed raw bytes representation of the public key.

        :return: The compressed raw bytes of the public key.
        :rtype: bytes
        """

        return self.verify_key.to_string("compressed")

    def raw_uncompressed(self) -> bytes:
        """
        Get the uncompressed raw bytes representation of the public key.

        :return: The uncompressed raw bytes of the public key.
        :rtype: bytes
        """

        return self.verify_key.to_string("uncompressed")

    def point(self) -> IPoint:
        """
        Get the elliptic curve point corresponding to the public key.

        :return: The elliptic curve point.
        :rtype: IPoint
        """

        return SLIP10Nist256p1Point(self.verify_key.pubkey.point)
