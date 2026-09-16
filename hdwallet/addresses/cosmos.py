#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.ripemd160 import ripemd160
from ..libs.bech32 import (
    bech32_encode, bech32_decode
)
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Cosmos
from ..crypto import sha256
from ..utils import bytes_to_string
from .iaddress import IAddress


class CosmosAddress(IAddress):

    hrp: str = Cosmos.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency or network.

        :return: The name "Cosmos".
        :rtype: str
        """

        return "Cosmos"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into a Bech32 Cosmos address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments, including "hrp".
        :type kwargs: Any

        :return: The encoded Bech32 Cosmos address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = ripemd160(sha256(
            public_key.raw_compressed()
        ))
        return bech32_encode(
            kwargs.get("hrp", cls.hrp), public_key_hash
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Bech32 Cosmos address into its corresponding public key hash.

        :param address: The Bech32 Cosmos address to be decoded.
        :type address: str
        :param kwargs: Additional keyword arguments, including "hrp".
        :type kwargs: Any

        :return: The decoded public key hash.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            kwargs.get("hrp", cls.hrp), address
        )
        return bytes_to_string(address_decode)
