#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
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
    get_bytes, integer_to_bytes, bytes_to_string
)
from .iaddress import IAddress


class P2SHAddress(IAddress):

    script_address_prefix: int = Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
    alphabet: str = Bitcoin.PARAMS.ALPHABET

    @staticmethod
    def name() -> str:
        """
        Return the name of the cryptocurrency, which is "P2SH".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "P2SH"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a P2SH address.

        :param public_key: The public key to encode. Can be bytes, str, or IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - script_address_prefix: Prefix for the script address (optional).
            - public_key_type: Type of the public key (optional).
            - alphabet: Custom alphabet for encoding (optional).
        :type kwargs: Any

        :return: The encoded P2SH address.
        :rtype: str
        """

        script_address_prefix: bytes = integer_to_bytes(
            kwargs.get("script_address_prefix", cls.script_address_prefix)
        )
        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = hash160(
            public_key.raw_compressed()
            if kwargs.get("public_key_type", PUBLIC_KEY_TYPES.COMPRESSED) == PUBLIC_KEY_TYPES.COMPRESSED else
            public_key.raw_uncompressed()
        )
        script_hash: bytes = hash160(get_bytes(
            "76a914" + bytes_to_string(public_key_hash) + "88ac"
        ))

        return ensure_string(check_encode(
            (script_address_prefix + script_hash), alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a P2SH address into its original public key hash.

        :param address: The P2SH address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - script_address_prefix: Prefix for the script address (optional).
            - alphabet: Custom alphabet for decoding (optional).
        :type kwargs: Any

        :return: The decoded public key hash as a string.
        :rtype: str
        """

        script_address_prefix: bytes = integer_to_bytes(
            kwargs.get("script_address_prefix", cls.script_address_prefix)
        )
        address_decode: bytes = check_decode(
            address, alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        )

        expected_length: int = 20 + len(script_address_prefix)
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        prefix_got: bytes = address_decode[:len(script_address_prefix)]
        if script_address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {script_address_prefix}, got: {prefix_got})")

        return bytes_to_string(address_decode[len(script_address_prefix):])
