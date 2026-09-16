#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from nacl.signing import SigningKey
from nacl import exceptions

from ....consts import SLIP10_ED25519_CONST
from ...iecc import (
    IPublicKey, IPrivateKey
)
from .public_key import SLIP10Ed25519PublicKey


class SLIP10Ed25519PrivateKey(IPrivateKey):

    signing_key: SigningKey

    def __init__(self, signing_key: SigningKey) -> None:
        """
        Initialize the class with a signing key.

        :param signing_key: The signing key used for cryptographic operations.
        :type signing_key: SigningKey
        """

        self.signing_key = signing_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Ed25519"

    @classmethod
    def from_bytes(cls, private_key: bytes) -> IPrivateKey:
        """
        Creates an instance of the class from a byte representation of a private key.

        :param private_key: The byte representation of the private key.
        :type private_key: bytes

        :return: An instance of the class initialized with the provided private key.
        :rtype: IPrivateKey
        """

        try:
            return cls(SigningKey(private_key))
        except (exceptions.RuntimeError, exceptions.ValueError) as ex:
            raise ValueError("Invalid private key bytes") from ex

    @staticmethod
    def length() -> int:
        """
        Returns the length of the private key in bytes.

        :return: The length of the private key in bytes.
        :rtype: int
        """

        return SLIP10_ED25519_CONST.PRIVATE_KEY_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Retrieves the underlying signing key object.

        :return: The underlying signing key object.
        :rtype: Any
        """

        return self.signing_key

    def raw(self) -> bytes:
        """
        Retrieves the raw bytes representation of the signing key.

        :return: Raw bytes of the signing key.
        :rtype: bytes
        """

        return bytes(self.signing_key)

    def public_key(self) -> IPublicKey:
        """
        Derives the public key from the signing key.

        :return: The public key corresponding to the signing key.
        :rtype: IPublicKey
        """

        return SLIP10Ed25519PublicKey(self.signing_key.verify_key)
