#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Sui
from ..crypto import blake2b_256
from ..utils import (
    bytes_to_string, integer_to_bytes
)
from .iaddress import IAddress


class SuiAddress(IAddress):

    key_type: bytes = integer_to_bytes(Sui.PARAMS.KEY_TYPE)
    address_prefix: str = Sui.PARAMS.ADDRESS_PREFIX

    @staticmethod
    def name() -> str:
        """
        Return the name "Sui".

        :return: The string "Sui".
        :rtype: str
        """

        return "Sui"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a string format using a specific hashing algorithm.

        :param public_key: The public key to encode, can be bytes, string, or an IPublicKey object.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded address as a string.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        return cls.address_prefix + bytes_to_string(blake2b_256(
            cls.key_type + public_key.raw_compressed()[1:]
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode an address string and validate its format.

        :param address: The address string to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded address string.
        :rtype: str
        """

        address_prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != address_prefix_got:
            raise ValueError(f"Invalid address_prefix (expected: {cls.address_prefix}, got: {address_prefix_got})")
        address_no_prefix = address[len(cls.address_prefix):]

        if len(address_no_prefix) != 64:
            raise ValueError(f"Invalid length (expected: {64}, got: {len(address_no_prefix)})")

        return address_no_prefix
