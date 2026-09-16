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
    IPublicKey, SLIP10Ed25519Blake2bPublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Nano
from ..crypto import blake2b_40
from ..utils import (
    get_bytes, bytes_reverse, bytes_to_string
)
from .iaddress import IAddress


class NanoAddress(IAddress):

    address_prefix: str = Nano.PARAMS.ADDRESS_PREFIX
    alphabet: str = Nano.PARAMS.ALPHABET
    payload_padding_decoded: bytes = Nano.PARAMS.PAYLOAD_PADDING_DECODED
    payload_padding_encoded: str = Nano.PARAMS.PAYLOAD_PADDING_ENCODED

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "Nano".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Nano"

    @classmethod
    def compute_checksum(cls, public_key: bytes) -> bytes:
        return bytes_reverse(blake2b_40(public_key))

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into an address using custom encoding.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key, SLIP10Ed25519Blake2bPublicKey
        )
        checksum: bytes = cls.compute_checksum(public_key.raw_compressed()[1:])
        payload: bytes = (
            cls.payload_padding_decoded + public_key.raw_compressed()[1:] + checksum
        )
        b32_encoded: str = encode_no_padding(bytes_to_string(payload), custom_alphabet=cls.alphabet)

        return cls.address_prefix + b32_encoded[len(cls.payload_padding_encoded):]

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode an address string into a public key using custom decoding.

        :param address: The address string to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded public key as a string.
        :rtype: str
        """

        prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {cls.address_prefix}, got: {prefix_got})")
        address_no_prefix: str = address[len(cls.address_prefix):]

        address_decode: bytes = get_bytes(decode(
            cls.payload_padding_encoded + address_no_prefix, custom_alphabet=cls.alphabet
        ))

        expected_length: int = (
            SLIP10Ed25519Blake2bPublicKey.compressed_length() + 5 + len(cls.payload_padding_decoded) - 1
        )
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        checksum: bytes = address_decode[len(cls.payload_padding_decoded):][-1 * 5:]
        public_key: bytes = address_decode[len(cls.payload_padding_decoded):][:-1 * 5]

        checksum_got: bytes = cls.compute_checksum(public_key)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {bytes_to_string(checksum)}, got: {bytes_to_string(checksum_got)})")

        if not SLIP10Ed25519Blake2bPublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Ed25519Blake2bPublicKey.name()} public key {bytes_to_string(public_key)}")

        return bytes_to_string(public_key)
