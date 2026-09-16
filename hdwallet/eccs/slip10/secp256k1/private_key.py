#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa import SigningKey
from ecdsa import (
    curves, keys
)

import coincurve

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import (
    IPublicKey, IPrivateKey
)
from .public_key import (
    SLIP10Secp256k1PublicKeyCoincurve, SLIP10Secp256k1PublicKeyECDSA
)


class SLIP10Secp256k1PrivateKeyCoincurve(IPrivateKey):

    signing_key: coincurve.PrivateKey

    def __init__(self, private_key: coincurve.PrivateKey) -> None:
        """
        Initializes an instance of SLIP10 Secp256k1 private key.

        :param private_key: The coincurve PrivateKey object representing the private key.
        :type private_key: coincurve.PrivateKey
        """

        self.signing_key = private_key

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, private_key: bytes) -> IPrivateKey:
        """
        Creates an instance of SLIP10 Secp256k1 private key from bytes.

        :param private_key: The private key bytes.
        :type private_key: bytes

        :return: An instance implementing the IPrivateKey interface.
        :rtype: IPrivateKey
        """

        if len(private_key) != cls.length():
            raise ValueError("Invalid private key bytes")

        try:
            return cls(coincurve.PrivateKey(private_key))
        except ValueError as ex:
            raise ValueError("Invalid private key bytes") from ex

    @staticmethod
    def length() -> int:
        """
        Returns the length of the SLIP10 Secp256k1 private key in bytes.

        :return: The length of the private key in bytes.
        :rtype: int
        """

        return SLIP10_SECP256K1_CONST.PRIVATE_KEY_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Retrieves the underlying signing key object.

        :return: The underlying signing key object.
        :rtype: Any
        """

        return self.signing_key

    def raw(self) -> bytes:
        """
        Retrieves the raw secret bytes of the signing key.

        :return: The raw secret bytes of the signing key.
        :rtype: bytes
        """

        return self.signing_key.secret

    def public_key(self) -> IPublicKey:
        """
        Retrieve the public key associated with this private key instance.

        :return: The public key object.
        :rtype: IPublicKey
        """

        return SLIP10Secp256k1PublicKeyCoincurve(self.signing_key.public_key)


class SLIP10Secp256k1PrivateKeyECDSA(IPrivateKey):

    signing_key: SigningKey

    def __init__(self, signing_key: SigningKey) -> None:
        """
        Initializes an instance with a signing key.

        :param signing_key: The signing key to be used for cryptographic operations.
        :type signing_key: SigningKey
        """

        self.signing_key = signing_key

    @staticmethod
    def name() -> str:
        """
        Returns the name of the SLIP10-Secp256k1 algorithm.

        :return: The name of the algorithm.
        :rtype: str
        """

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> IPrivateKey:
        """
        Creates a private key instance from the given bytes.

        :param key_bytes: The bytes representing the private key.
        :type key_bytes: bytes

        :return: An instance of IPrivateKey corresponding to the given bytes.
        :rtype: IPrivateKey
        """

        try:
            return cls(
                SigningKey.from_string(
                    key_bytes, curve=curves.SECP256k1
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid private key bytes") from ex

    @staticmethod
    def length() -> int:
        """
        Returns the length of the private key in bytes for SLIP10 SECP256k1 curve.

        :return: Length of the private key in bytes.
        :rtype: int

        """

        return SLIP10_SECP256K1_CONST.PRIVATE_KEY_BYTE_LENGTH

    def underlying_object(self) -> Any:
        """
        Return the underlying signing key object.

        :return: The underlying signing key object.
        :rtype: Any
        """

        return self.signing_key

    def raw(self) -> bytes:
        """
        Return the raw bytes representation of the private key.

        :return: The raw bytes of the private key.
        :rtype: bytes
        """

        return self.signing_key.to_string()

    def public_key(self) -> IPublicKey:
        """
        Retrieve the public key associated with this private key instance.

        :return: The public key object.
        :rtype: IPublicKey
        """

        return SLIP10Secp256k1PublicKeyECDSA(self.signing_key.get_verifying_key())


if SLIP10_SECP256K1_CONST.USE == "coincurve":
    SLIP10Secp256k1PrivateKey = SLIP10Secp256k1PrivateKeyCoincurve
elif SLIP10_SECP256K1_CONST.USE == "ecdsa":
    SLIP10Secp256k1PrivateKey = SLIP10Secp256k1PrivateKeyECDSA
else:
    raise Exception(
        f"Invalid SLIP10-Secp256k1 use, (expected: 'coincurve' or 'ecdsa', got: '{SLIP10_SECP256K1_CONST.USE}')"
    )
