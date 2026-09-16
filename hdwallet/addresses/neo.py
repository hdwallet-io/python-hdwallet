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
from ..eccs import (
    IPublicKey, SLIP10Nist256p1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Neo
from ..crypto import hash160
from ..utils import (
    integer_to_bytes, bytes_to_string
)
from .iaddress import IAddress


class NeoAddress(IAddress):

    address_prefix: bytes = integer_to_bytes(Neo.PARAMS.ADDRESS_PREFIX)
    address_suffix: bytes = integer_to_bytes(Neo.PARAMS.ADDRESS_SUFFIX)
    address_version: bytes = integer_to_bytes(Neo.PARAMS.ADDRESS_VERSION)

    alphabet: bytes = Neo.PARAMS.ALPHABET

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "Neo".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Neo"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a cryptocurrency address using SLIP-10 NIST P-256 public key.

        :param public_key: The public key to encode. Can be bytes, str, or IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - address_version: Version of the address (optional).
            - alphabet: Custom alphabet for encoding (optional).
        :type kwargs: Any

        :return: The encoded cryptocurrency address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Nist256p1PublicKey
        )
        payload: bytes = (
            cls.address_prefix + public_key.raw_compressed() + cls.address_suffix
        )
        payload_hash: bytes = hash160(payload)

        return ensure_string(check_encode(
            (kwargs.get("address_version", cls.address_version) + payload_hash), alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a cryptocurrency address into its public key using SLIP-10 NIST P-256 public key.

        :param address: The address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - alphabet: Custom alphabet for decoding (optional).
            - address_version: Version of the address (optional).
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        address_decode: bytes = check_decode(
            address, alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        )
        address_version: bytes = kwargs.get("address_version", cls.address_version)

        expected_length: int = 20 + len(address_version)
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        address_version_got: bytes = integer_to_bytes(address_decode[0])
        if address_version != address_version_got:
            raise ValueError(f"Invalid address version (expected: {address_version}, got: {address_version_got})")

        return bytes_to_string(address_decode[1:])
