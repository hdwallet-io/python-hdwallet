#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import (
    ensure_string, check_encode, check_decode
)
from ..consts import PUBLIC_KEY_TYPES
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Bitcoin
from ..crypto import hash160
from ..utils import (
    integer_to_bytes, bytes_to_string
)
from .iaddress import IAddress


class P2PKHAddress(IAddress):

    public_key_address_prefix: int = Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    alphabet: str = Bitcoin.PARAMS.ALPHABET

    @staticmethod
    def name() -> str:
        """
        Return the name of the cryptocurrency, which is "P2PKH".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "P2PKH"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into an address using a specified address prefix and alphabet.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - public_key_address_prefix: Address prefix for the public key (optional).
            - public_key_type: Type of the public key (optional).
            - alphabet: Custom alphabet for encoding (optional).
        :type kwargs: Any

        :return: The encoded address.
        :rtype: str
        """

        public_key_address_prefix: bytes = integer_to_bytes(
            kwargs.get("public_key_address_prefix", cls.public_key_address_prefix)
        )
        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = hash160(
            public_key.raw_compressed()
            if kwargs.get("public_key_type", PUBLIC_KEY_TYPES.COMPRESSED) == PUBLIC_KEY_TYPES.COMPRESSED else
            public_key.raw_uncompressed()
        )

        return ensure_string(check_encode(
            (public_key_address_prefix + public_key_hash), alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode an address string into a public key hash using a specified address prefix and alphabet.

        :param address: The address string to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - public_key_address_prefix: Address prefix for the public key (optional).
            - alphabet: Custom alphabet for decoding (optional).
        :type kwargs: Any

        :return: The decoded public key hash as a string.
        :rtype: str
        """

        public_key_address_prefix: bytes = integer_to_bytes(
            kwargs.get("public_key_address_prefix", cls.public_key_address_prefix)
        )
        address_decode: bytes = check_decode(
            address, alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        )

        expected_length: int = 20 + len(public_key_address_prefix)
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        prefix_got: bytes = address_decode[:len(public_key_address_prefix)]
        if public_key_address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {public_key_address_prefix}, got: {prefix_got})")

        return bytes_to_string(address_decode[len(public_key_address_prefix):])
