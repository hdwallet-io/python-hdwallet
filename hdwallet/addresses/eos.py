#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import (
    ensure_string, encode, decode
)
from ..libs.ripemd160 import ripemd160
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import EOS
from ..utils import bytes_to_string
from .iaddress import IAddress


class EOSAddress(IAddress):

    address_prefix: str = EOS.PARAMS.ADDRESS_PREFIX
    checksum_length: int = EOS.PARAMS.CHECKSUM_LENGTH

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name "EOS".
        :rtype: str
        """

        return "EOS"

    @classmethod
    def compute_checksum(cls, pub_key_bytes: bytes) -> bytes:
        return ripemd160(pub_key_bytes)[:cls.checksum_length]

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into an EOS address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded EOS address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        checksum: bytes = cls.compute_checksum(public_key.raw_compressed())

        return cls.address_prefix + ensure_string(encode(
            (public_key.raw_compressed() + checksum)
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given EOS address into its corresponding public key.

        :param address: The EOS address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {cls.address_prefix}, got: {prefix_got})")
        address_no_prefix: str = address[len(cls.address_prefix):]

        address_decode: bytes = decode(address_no_prefix)

        expected_length: int = SLIP10Secp256k1PublicKey.compressed_length() + cls.checksum_length
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        checksum: bytes = address_decode[-1 * cls.checksum_length:]
        public_key: bytes = address_decode[:-1 * cls.checksum_length]

        checksum_got: bytes = cls.compute_checksum(public_key)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {checksum.hex()}, got: {checksum_got.hex()})")

        if not SLIP10Secp256k1PublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Secp256k1PublicKey.name()} public key {public_key.hex()}")

        return bytes_to_string(public_key)
