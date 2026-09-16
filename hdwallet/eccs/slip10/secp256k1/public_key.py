#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa import VerifyingKey
from ecdsa.ecdsa import curve_secp256k1
from ecdsa import (
    curves, ellipticcurve, keys
)

import coincurve

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import (
    IPoint, IPublicKey
)
from .point import (
    SLIP10Secp256k1PointCoincurve, SLIP10Secp256k1PointECDSA
)


class SLIP10Secp256k1PublicKeyCoincurve(IPublicKey):

    verify_key: coincurve.PublicKey

    def __init__(self, public_key: coincurve.PublicKey) -> None:
        """
        Initialize the public key object.

        :param public_key: The coincurve PublicKey object representing the public key.
        :type public_key: coincurve.PublicKey
        """

        self.verify_key = public_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, public_key: bytes) -> IPublicKey:
        """
        Create a public key instance from a byte representation.

        :param public_key: The byte representation of the public key.
        :type public_key: bytes

        :return: An instance of the public key created from the byte representation.
        :rtype: IPublicKey
        """

        try:
            return cls(coincurve.PublicKey(public_key))
        except ValueError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def from_point(cls, point: IPoint) -> IPublicKey:
        """
        Create a public key instance from a given elliptic curve point.

        :param point: The elliptic curve point containing x and y coordinates.
        :type point: IPoint

        :return: An instance of the public key derived from the elliptic curve point.
        :rtype: IPublicKey
        """

        try:
            return cls(
                coincurve.PublicKey.from_point(
                    point.x(), point.y()
                )
            )
        except ValueError as ex:
            raise ValueError("Invalid public key point") from ex

    @staticmethod
    def compressed_length() -> int:
        """
        Get the length of the compressed public key in bytes.

        :return: Length of the compressed public key in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_COMPRESSED_BYTE_LENGTH

    @staticmethod
    def uncompressed_length() -> int:
        """
        Returns the length of an uncompressed public key in bytes.

        :return: The length of an uncompressed public key in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Returns the underlying verification key object.

        :return: The underlying verification key object.
        :rtype: Any
        """

        return self.verify_key

    def raw_compressed(self) -> bytes:
        """
        Retrieves the raw compressed representation of the public key.

        :return: The compressed public key bytes.
        :rtype: bytes
        """

        return self.verify_key.format(True)

    def raw_uncompressed(self) -> bytes:
        """
        Get the uncompressed raw representation of the verifying key.

        :return: Uncompressed raw bytes of the verifying key.
        :rtype: bytes
        """

        return self.verify_key.format(False)

    def point(self) -> IPoint:
        """
        Get the cryptographic point associated with the verifying key.

        :return: The cryptographic point.
        :rtype: IPoint
        """

        point = self.verify_key.point()
        return SLIP10Secp256k1PointCoincurve.from_coordinates(
            point[0], point[1]
        )


class SLIP10Secp256k1PublicKeyECDSA(IPublicKey):

    verify_key: VerifyingKey

    def __init__(self, verify_key: VerifyingKey) -> None:
        """
        Initialize the instance with a verifying key.

        :param verify_key: The verifying key used for cryptographic operations.
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

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, public_key: bytes) -> IPublicKey:
        """
        Create a public key instance from bytes representation.

        :param public_key: The bytes representation of the public key.
        :type public_key: bytes

        :return: An instance of the public key derived from the given bytes.
        :rtype: IPublicKey
        """

        try:
            return cls(
                VerifyingKey.from_string(
                    public_key, curve=curves.SECP256k1
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def from_point(cls, point: IPoint) -> IPublicKey:
        """
        Create a public key instance from an elliptic curve point.

        :param point: The elliptic curve point representing the public key.
        :type point: IPoint

        :return: An instance of the public key derived from the given point.
        :rtype: IPublicKey
        """

        try:
            return cls(
                VerifyingKey.from_public_point(
                    ellipticcurve.Point(
                        curve_secp256k1, point.x(), point.y()
                    ),
                    curve=curves.SECP256k1
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid public key point") from ex

    @staticmethod
    def compressed_length() -> int:
        """
        Returns the length of a compressed public key in bytes.

        :return: The length of a compressed public key in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_COMPRESSED_BYTE_LENGTH

    @staticmethod
    def uncompressed_length() -> int:
        """
        Returns the length of an uncompressed public key in bytes.

        :return: The length of an uncompressed public key in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Returns the underlying verification key object.

        :return: The underlying verification key object.
        :rtype: Any
        """

        return self.verify_key

    def raw_compressed(self) -> bytes:
        """
        Retrieves the raw compressed representation of the public key.

        :return: The compressed public key bytes.
        :rtype: bytes
        """

        return self.verify_key.to_string("compressed")

    def raw_uncompressed(self) -> bytes:
        """
        Retrieves the raw uncompressed representation of the public key.

        :return: The uncompressed public key bytes.
        :rtype: bytes
        """

        return self.verify_key.to_string("uncompressed")

    def point(self) -> IPoint:
        """
        Retrieves the point object associated with the public key.

        :return: The point object implementing the IPoint interface.
        :rtype: IPoint
        """

        return SLIP10Secp256k1PointECDSA(self.verify_key.pubkey.point)


if SLIP10_SECP256K1_CONST.USE == "coincurve":
    SLIP10Secp256k1PublicKey = SLIP10Secp256k1PublicKeyCoincurve
elif SLIP10_SECP256K1_CONST.USE == "ecdsa":
    SLIP10Secp256k1PublicKey = SLIP10Secp256k1PublicKeyECDSA
else:
    raise Exception(
        f"Invalid SLIP10-Secp256k1 use, (expected: 'coincurve' or 'ecdsa', got: '{SLIP10_SECP256K1_CONST.USE}')"
    )
