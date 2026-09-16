#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from nacl.signing import VerifyKey

from ....consts import KHOLAW_ED25519_CONST
from ....libs.ed25519 import point_scalar_mul_base
from ...slip10.ed25519 import SLIP10Ed25519PrivateKey
from ...iecc import (
    IPublicKey, IPrivateKey
)
from .public_key import KholawEd25519PublicKey


class KholawEd25519PrivateKey(IPrivateKey):

    signing_key: IPrivateKey
    extended_key: bytes

    def __init__(self, private_key: IPrivateKey, extended_key: bytes) -> None:
        """
        Initializes a new instance of the class with a private key and an extended key.

        :param private_key: The private key to be used. Must be an instance of `SLIP10Ed25519PrivateKey`.
        :type private_key: IPrivateKey
        :param extended_key: The extended key associated with the private key.
                            Must be of length specified by `SLIP10Ed25519PrivateKey.length()`.
        :type extended_key: bytes
        """

        if not isinstance(private_key, SLIP10Ed25519PrivateKey):
            raise TypeError("Invalid private key object type")
        if len(extended_key) != SLIP10Ed25519PrivateKey.length():
            raise ValueError("Invalid extended key length")

        self.signing_key = private_key
        self.extended_key = extended_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "Kholaw-Ed25519"

    @classmethod
    def from_bytes(cls, private_key: bytes) -> IPrivateKey:
        """
        Creates an instance of the private key from a byte sequence.

        :param private_key: The byte sequence representing the private key.
        :type private_key: bytes

        :return: An instance of the private key.
        :rtype: IPrivateKey
        """

        return cls(
            SLIP10Ed25519PrivateKey.from_bytes(
                private_key[:SLIP10Ed25519PrivateKey.length()]
            ),
            private_key[SLIP10Ed25519PrivateKey.length():]
        )

    @staticmethod
    def length() -> int:
        """
        Returns the length of the private key in bytes.

        This method retrieves the constant value representing the byte length of the private key
        for the KholawEd25519 algorithm.

        :return: The length of the private key in bytes.
        :rtype: int
        """

        return KHOLAW_ED25519_CONST.PRIVATE_KEY_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Retrieves the underlying object of the signing key.

        :return: The underlying object of the signing key.
        :rtype: Any
        """

        return self.signing_key.underlying_object()

    def raw(self) -> bytes:
        """
        Returns the raw byte representation of the signing key combined with the extended key.

        :return: The raw byte sequence of the signing key and extended key.
        :rtype: bytes
        """

        return self.signing_key.raw() + self.extended_key

    def public_key(self) -> IPublicKey:
        """
        Generates the public key corresponding to the signing key.

        :return: The generated public key.
        :rtype: IPublicKey
        """

        return KholawEd25519PublicKey(VerifyKey(
            point_scalar_mul_base(bytes(self.signing_key.underlying_object()))
        ))
