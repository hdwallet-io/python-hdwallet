#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ed25519_blake2b import VerifyingKey

from .....consts import SLIP10_ED25519_CONST
from ....iecc import (
    IPoint, IPublicKey
)
from .....libs.ed25519 import point_is_on_curve
from .....utils import bytes_to_integer
from .point import SLIP10Ed25519Blake2bPoint


class SLIP10Ed25519Blake2bPublicKey(IPublicKey):

    verify_key: VerifyingKey

    def __init__(self, verify_key: VerifyingKey) -> None:
        """
        Initializes an instance of the public key with the provided VerifyingKey.

        :param verify_key: The VerifyingKey object representing the public key.
        :type verify_key: VerifyingKey

        :return: No return
        :rtype: NoneType
        """

        self.verify_key = verify_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Ed25519-Blake2b"

    @classmethod
    def from_bytes(cls, public_key: bytes) -> IPublicKey:
        """
        Constructs an instance of the public key from its byte representation.

        :param public_key: The byte representation of the public key.
        :type public_key: bytes

        :return: An instance of IPublicKey.
        :rtype: IPublicKey
        """

        if (len(public_key) == SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH + len(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)
                and public_key[0] == bytes_to_integer(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)):
            public_key = public_key[1:]
        elif len(public_key) != SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH:
            raise ValueError("Invalid public key bytes")

        if not point_is_on_curve(public_key):
            raise ValueError("Invalid public key bytes")

        return cls(VerifyingKey(public_key))

    @classmethod
    def from_point(cls, point: IPoint) -> IPublicKey:
        """
        Converts a point representation of a public key to an instance of IPublicKey.

        :param point: The point object representing the public key.
        :type point: IPoint

        :return: An instance of IPublicKey.
        :rtype: IPublicKey
        """

        return cls.from_bytes(point.raw_encoded())

    @staticmethod
    def compressed_length() -> int:
        """
        Returns the compressed length of the public key.

        :return: The compressed length of the public key.
        :rtype: int
        """

        return SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH + len(SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX)

    @staticmethod
    def uncompressed_length() -> int:
        """
        Returns the uncompressed length of the public key.

        :return: The uncompressed length of the public key.
        :rtype: int
        """

        return SLIP10Ed25519Blake2bPublicKey.compressed_length()

    def underlying_object(self) -> Any:
        """
        Retrieves the underlying object representing the public key.

        :return: The underlying object representing the public key.
        :rtype: Any
        """

        return self.verify_key

    def raw_compressed(self) -> bytes:
        """
        Retrieves the raw compressed representation of the public key.

        This method returns the raw bytes of the compressed public key.
        It prepends the public key prefix defined in SLIP10_ED25519_CONST to the compressed key.

        :return: The raw compressed bytes of the public key.
        :rtype: bytes
        """

        return SLIP10_ED25519_CONST.PUBLIC_KEY_PREFIX + self.verify_key.to_bytes()

    def raw_uncompressed(self) -> bytes:
        """
        Retrieves the raw uncompressed representation of the public key.

        :return: The raw uncompressed bytes of the public key.
        :rtype: bytes
        """

        return self.raw_compressed()

    def point(self) -> IPoint:
        """
        Retrieves the SLIP10 Ed25519 Blake2b point corresponding to the public key.

        :return: The point corresponding to the public key.
        :rtype: IPoint
        """

        return SLIP10Ed25519Blake2bPoint(self.verify_key.to_bytes())
