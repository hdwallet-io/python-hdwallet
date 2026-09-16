#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ed25519_blake2b import SigningKey

from .....consts import SLIP10_ED25519_CONST
from ....iecc import (
    IPublicKey, IPrivateKey
)
from .public_key import SLIP10Ed25519Blake2bPublicKey


class SLIP10Ed25519Blake2bPrivateKey(IPrivateKey):

    signing_key: SigningKey

    def __init__(self, signing_key: SigningKey) -> None:
        """
        Initializes the class instance with a signing key.

        :param signing_key: The signing key object used for cryptographic operations.
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

        return "SLIP10-Ed25519-Blake2b"

    @classmethod
    def from_bytes(cls, private_key: bytes) -> IPrivateKey:
        """
        Creates an instance of the private key from its byte representation.

        :param private_key: The byte representation of the private key.
        :type private_key: bytes

        :return: An instance of the private key.
        :rtype: IPrivateKey
        """

        try:
            return cls(SigningKey(private_key))
        except ValueError as ex:
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
        Returns the underlying object of the signing key.

        :return: The underlying object of the signing key.
        :rtype: Any
        """

        return self.signing_key

    def raw(self) -> bytes:
        """
        Returns the raw bytes representation of the signing key.

        :return: The raw bytes of the signing key.
        :rtype: bytes
        """

        return self.signing_key.to_bytes()

    def public_key(self) -> IPublicKey:
        """
        Returns the public key associated with this signing key.

        :return: The public key as an instance of IPublicKey.
        :rtype: IPublicKey
        """

        return SLIP10Ed25519Blake2bPublicKey(self.signing_key.get_verifying_key())
