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
from ..cryptocurrencies import Ethereum
from ..crypto import keccak256
from ..utils import bytes_to_string
from .iaddress import IAddress


class EthereumAddress(IAddress):

    address_prefix: str = Ethereum.PARAMS.ADDRESS_PREFIX

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Ethereum"

    @staticmethod
    def checksum_encode(address: str) -> str:
        output: str = ""
        address_hash: str = bytes_to_string(
            keccak256(address.lower())
        )
        for i, c in enumerate(address):
            if int(address_hash[i], 16) >= 8:
                output += c.upper()
            else:
                output += c
        return output

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into a Cosmos address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments, including "skip_checksum_encode".
        :type kwargs: Any

        :return: The encoded Cosmos address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        address: str = bytes_to_string(
            keccak256(public_key.raw_uncompressed()[1:])
        )[24:]
        return cls.address_prefix + (
            address if kwargs.get("skip_checksum_encode", False) else cls.checksum_encode(address)
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Cosmos address into its corresponding public key hash.

        :param address: The Cosmos address to be decoded.
        :type address: str
        :param kwargs: Additional keyword arguments, including "skip_checksum_encode".
        :type kwargs: Any

        :return: The decoded public key hash.
        :rtype: str
        """

        address_prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != address_prefix_got:
            raise ValueError(f"Invalid address_prefix (expected: {cls.address_prefix}, got: {address_prefix_got})")
        address_no_prefix = address[len(cls.address_prefix):]

        if len(address_no_prefix) != 40:
            raise ValueError(f"Invalid length (expected: {40}, got: {len(address_no_prefix)})")
        # Check checksum encoding
        if not kwargs.get("skip_checksum_encode", False) and address_no_prefix != cls.checksum_encode(address_no_prefix):
            print(address_no_prefix, cls.checksum_encode(address_no_prefix))
            raise ValueError("Invalid checksum encode")

        return address_no_prefix.lower()
