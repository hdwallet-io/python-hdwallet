#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa import SigningKey
from ecdsa import (
    curves, keys
)

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import (
    IPublicKey, IPrivateKey
)
from .public_key import SLIP10Nist256p1PublicKey


class SLIP10Nist256p1PrivateKey(IPrivateKey):

    signing_key: SigningKey

    def __init__(self, signing_key: SigningKey) -> None:
        """
        Initialize the private key object.

        :param signing_key: The signing key object.
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

        return "SLIP10-Nist256p1"

    @classmethod
    def from_bytes(cls, private_key: bytes) -> IPrivateKey:
        """
        Create a private key object from a byte string.

        :param private_key: The byte string representing the private key.
        :type private_key: bytes

        :return: An instance of the private key.
        :rtype: IPrivateKey
        """

        try:
            return cls(
                SigningKey.from_string(
                    private_key, curve=curves.NIST256p
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid private key bytes") from ex

    @staticmethod
    def length() -> int:
        """
        Get the length of the private key in bytes.

        :return: The private key length in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PRIVATE_KEY_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Retrieve the underlying signing key object.

        :return: The underlying signing key object.
        :rtype: Any
        """

        return self.signing_key

    def raw(self) -> bytes:
        """
        Retrieve the raw byte representation of the signing key.

        :return: The raw bytes of the signing key.
        :rtype: bytes
        """

        return self.signing_key.to_string()

    def public_key(self) -> IPublicKey:
        """
        Retrieve the corresponding public key for the signing key.

        :return: The public key associated with the signing key.
        :rtype: IPublicKey
        """

        return SLIP10Nist256p1PublicKey(self.signing_key.get_verifying_key())
