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
from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Solana
from ..utils import bytes_to_string
from .iaddress import IAddress


class SolanaAddress(IAddress):

    alphabet: str = Solana.PARAMS.ALPHABET

    @staticmethod
    def name() -> str:
        """
        Return the name of the cryptocurrency, which is "Solana".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Solana"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a Solana address.

        :param public_key: The public key to encode. It can be a bytes object, a string, or an IPublicKey instance.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded Solana address as a string.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )

        return ensure_string(encode(public_key.raw_compressed()[1:]))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a Solana address back into its corresponding public key.

        :param address: The Solana address to decode.
        :type address: str

        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded public key as a string.
        :rtype: str
        """

        public_key: bytes = decode(address)

        expected_length = SLIP10Ed25519PublicKey.compressed_length() - 1
        if len(public_key) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(public_key)})")

        if not SLIP10Ed25519PublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Ed25519PublicKey.name()} public key {bytes_to_string(public_key)}")

        return bytes_to_string(public_key)
