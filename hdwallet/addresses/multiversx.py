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
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import MultiversX
from ..utils import bytes_to_string
from .iaddress import IAddress


class MultiversXAddress(IAddress):

    hrp: str = MultiversX.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "MultiversX".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "MultiversX"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode the public key into a string format using Bech32 encoding.

        :param public_key: The public key to encode, can be bytes, str, or IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
        :type kwargs: Any

        :return: The encoded public key as a string.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        return bech32_encode(
            kwargs.get("hrp", cls.hrp), public_key.raw_compressed()[1:]
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode an address string using Bech32 decoding.

        :param address: The address string to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
        :type kwargs: Any

        :return: The decoded address as a string.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            kwargs.get("hrp", cls.hrp), address
        )
        return bytes_to_string(address_decode)
