#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from nacl.signing import VerifyKey
from nacl import exceptions

from ....consts import SLIP10_ED25519_CONST
from ....libs.ed25519 import point_is_on_curve
from ....utils import bytes_to_integer
from ...iecc import (
    IPoint, IPublicKey
)
from .point import SLIP10Ed25519Point


class SLIP10Ed25519PublicKey(IPublicKey):

    verify_key: VerifyKey

    def __init__(self, verify_key: VerifyKey) -> None:
        """
        Initialize the class with a verification key.

        :param verify_key: The verification key used for cryptographic operations.
        :type verify_key: VerifyKey
        """

        self.verify_key = verify_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Ed25519"

    @classmethod
    def from_bytes(cls, public_key: bytes) -> IPublicKey:
        """
        Create an instance of the class from raw bytes representing a public key.

        This method verifies and parses the provided public key bytes.

        :param public_key: The bytes representing the public key.
        :type public_key: bytes
        :return: An instance of IPublicKey.
        :rtype: IPublicKey
        """

        if (len(public_key) == SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH + len(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)
                and public_key[0] == bytes_to_integer(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)):
            public_key = public_key[1:]

        if not point_is_on_curve(public_key):
            raise ValueError("Invalid public key bytes")

        try:
            return cls(VerifyKey(public_key))
        except (exceptions.RuntimeError, exceptions.ValueError) as ex:
            raise ValueError("Invalid public key bytes") from ex

    @classmethod
    def from_point(cls, point: IPoint) -> IPublicKey:
        """
        Calculate the length of the compressed public key.

        :return: The length of the compressed public key in bytes.
        :rtype: int
        """

        return cls.from_bytes(point.raw_encoded())

    @staticmethod
    def compressed_length() -> int:
        """
        Returns the total length of the compressed Ed25519 public key, including the prefix.

        :return: The total length of the compressed public key.
        :rtype: int
        """

        return SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH + len(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)

    @staticmethod
    def uncompressed_length() -> int:
        """
        Retrieve the underlying object representing the public key.

        :return: The underlying object of the public key.
        :rtype: Any
        """

        return SLIP10Ed25519PublicKey.compressed_length()

    def underlying_object(self) -> Any:
        """
        Returns the underlying verify key object associated with this Ed25519 Monero public key.

        :return: The underlying verify key object.
        :rtype: Any
        """

        return self.verify_key

    def raw_compressed(self) -> bytes:
        """
        Retrieve the compressed raw representation of the public key.

        :return: Compressed raw bytes of the public key.
        :rtype: bytes
        """

        return SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX + bytes(self.verify_key)

    def raw_uncompressed(self) -> bytes:
        """
        Retrieve the uncompressed raw representation of the public key.

        :return: Uncompressed raw bytes of the public key.
        :rtype: bytes
        """

        return self.raw_compressed()

    def point(self) -> IPoint:
        """
        Retrieve the point representation of the public key.

        :return: An instance of IPoint representing the public key point.
        :rtype: IPoint
        """

        return SLIP10Ed25519Point(bytes(self.verify_key))
