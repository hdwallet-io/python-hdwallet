#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base32 import (
    encode_no_padding, decode
)
from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Algorand
from ..crypto import sha512_256
from ..utils import (
    get_bytes, bytes_to_string
)
from .iaddress import IAddress


class AlgorandAddress(IAddress):

    checksum_length: int = Algorand.PARAMS.CHECKSUM_LENGTH

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the cryptocurrency, which is "Algorand".
        :rtype: str
        """
        return "Algorand"

    @staticmethod
    def compute_checksum(public_key: bytes) -> bytes:
        return sha512_256(public_key)[-1 * 4:]

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes a public key to a string format with a checksum.

        :param public_key: The public key to be encoded. It can be in bytes, string, or IPublicKey format.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.

        :return: The encoded public key string with a checksum.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        return encode_no_padding(bytes_to_string(
            public_key.raw_compressed()[1:] + cls.compute_checksum(public_key.raw_compressed()[1:])
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes an encoded address string to a public key, verifying its checksum.

        :param address: The encoded address string.
        :type address: str
        :param kwargs: Additional keyword arguments.

        :return: The decoded public key as a string.
        :rtype: str
        """

        address_decode: bytes = get_bytes(decode(address))

        expected_length: int = (
            SLIP10Ed25519PublicKey.compressed_length() + cls.checksum_length - 1
        )
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        checksum: bytes = address_decode[-1 * cls.checksum_length:]
        public_key: bytes = address_decode[:-1 * cls.checksum_length]

        checksum_got: bytes = cls.compute_checksum(public_key)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {checksum.hex()}, got: {checksum_got.hex()})")

        if not SLIP10Ed25519PublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Ed25519PublicKey.name()} public key {public_key.hex()}")

        return bytes_to_string(public_key)
