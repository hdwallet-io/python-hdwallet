#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.bech32 import (
    bech32_encode, bech32_decode
)
from ..eccs import IPublicKey
from ..cryptocurrencies import OKTChain
from ..utils import (
    get_bytes, bytes_to_string
)
from .ethereum import EthereumAddress
from .iaddress import IAddress


class OKTChainAddress(IAddress):

    hrp: str = OKTChain.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "OKT-Chain".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "OKT-Chain"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into an address using Bech32 encoding.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
        :type kwargs: Any

        :return: The encoded address.
        :rtype: str
        """

        return bech32_encode(
            cls.hrp, get_bytes(EthereumAddress.encode(
                public_key, skip_checksum_encode=True
            )[2:])  # remove "0x" at the beginning
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a OKT-Chain address from Bech32 encoding.

        :param address: The OKT-Chain address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments:
            - hrp (str, optional): Human-readable part for the Bech32 encoding. Defaults to cls.hrp.

        :return: Decoded OKT-Chain address.
        :rtype: str
        """

        return EthereumAddress.decode(
            EthereumAddress.address_prefix + bytes_to_string(
                bech32_decode(cls.hrp, address)[1]
            ), skip_checksum_encode=True
        )
