#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.bech32 import (
    bech32_encode, bech32_decode
)
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Injective
from ..utils import (
    get_bytes, bytes_to_string
)
from .ethereum import EthereumAddress
from .iaddress import IAddress


class InjectiveAddress(IAddress):

    hrp: str = Injective.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "Injective".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Injective"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes a public key into an Injective address using Bech32 encoding.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded Injective address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )

        return bech32_encode(
            kwargs.get("hrp", cls.hrp), get_bytes(EthereumAddress.encode(public_key)[2:])
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes an Injective address from Bech32 encoding.

        :param address: The Injective address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            kwargs.get("hrp", cls.hrp), address
        )

        expected_length: int = 20
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        return bytes_to_string(address_decode)
