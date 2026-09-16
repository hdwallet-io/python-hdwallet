#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Icon
from ..crypto import sha3_256
from ..utils import (
    get_bytes, bytes_to_string
)
from .iaddress import IAddress


class IconAddress(IAddress):

    address_prefix: str = Icon.PARAMS.ADDRESS_PREFIX
    key_hash_length: int = Icon.PARAMS.KEY_HASH_LENGTH

    @staticmethod
    def name() -> str:
        """
        Returns the name of the blockchain.

        :return: The name of the blockchain.
        :rtype: str
        """

        return "Icon"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into an Icon address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded Icon address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = sha3_256(
            public_key.raw_uncompressed()[1:]
        )[-cls.key_hash_length:]

        return cls.address_prefix + bytes_to_string(public_key_hash)

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Icon address into its corresponding public key hash.

        :param address: The Icon address to be decoded.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded public key hash.
        :rtype: str
        """

        prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {cls.address_prefix}, got: {prefix_got})")
        address_no_prefix: str = address[len(cls.address_prefix):]

        public_key_hash: bytes = get_bytes(address_no_prefix)

        if len(public_key_hash) != cls.key_hash_length:
            raise ValueError(f"Invalid length (expected: {cls.key_hash_length}, got: {len(public_key_hash)})")

        return bytes_to_string(public_key_hash)
