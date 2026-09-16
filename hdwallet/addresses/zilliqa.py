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
from ..cryptocurrencies import Zilliqa
from ..crypto import sha256
from ..utils import bytes_to_string
from .iaddress import IAddress


class ZilliqaAddress(IAddress):

    hrp: str = Zilliqa.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Return the name associated with the Zilliqa blockchain.

        :return: The name "Zilliqa".
        :rtype: str
        """

        return "Zilliqa"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a Zilliqa address using Bech32 encoding.

        :param public_key: The public key to encode, which can be bytes, str, or an IPublicKey object.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments:
            - hrp (str, optional): Human-readable part for the Bech32 encoding. Defaults to cls.hrp.

        :return: Encoded Zilliqa address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = sha256(public_key.raw_compressed())

        return bech32_encode(
            kwargs.get("hrp", cls.hrp), public_key_hash[-20:]
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a Zilliqa address from Bech32 encoding.

        :param address: The Zilliqa address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments:
            - hrp (str, optional): Human-readable part for the Bech32 encoding. Defaults to cls.hrp.

        :return: Decoded Zilliqa address.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            kwargs.get("hrp", cls.hrp), address
        )

        if len(address_decode) != 20:
            raise ValueError(f"Invalid length (expected: {20}, got: {len(address_decode)})")

        return bytes_to_string(address_decode)
