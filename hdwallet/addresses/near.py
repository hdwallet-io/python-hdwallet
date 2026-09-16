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
from ..utils import (
    get_bytes, bytes_to_string
)
from .iaddress import IAddress


class NearAddress(IAddress):

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "Near".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Near"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes a public key into a string format.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded public key as a string.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        return bytes_to_string(public_key.raw_compressed())[2:]

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes an address string.

        :param address: The address string to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded address string.
        :rtype: str
        """

        expected_length: int = 32
        if len(get_bytes(address)) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(get_bytes(address))})")

        validate_and_get_public_key(
            public_key=get_bytes(address), public_key_cls=SLIP10Ed25519PublicKey
        )
        return address
