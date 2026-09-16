#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..eccs import IPublicKey
from ..cryptocurrencies import Avalanche
from ..exceptions import AddressError
from .cosmos import CosmosAddress
from .iaddress import IAddress


class AvalancheAddress(IAddress):

    hrp: str = Avalanche.NETWORKS.MAINNET.HRP
    address_types: dict = {
        "p-chain": Avalanche.PARAMS.ADDRESS_TYPES.P_CHAIN,
        "x-chain": Avalanche.PARAMS.ADDRESS_TYPES.X_CHAIN
    }

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Avalanche"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into an Avalanche address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments, including "address_type".
        :type kwargs: Any

        :return: The encoded Avalanche address.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: str = cls.address_types[Avalanche.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Avalanche.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Avalanche.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: str = cls.address_types[kwargs.get("address_type")]

        return address_type + CosmosAddress.encode(
            public_key=public_key, hrp=cls.hrp
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Avalanche address into its corresponding public key.

        :param address: The Avalanche address to be decoded.
        :type address: str
        :param kwargs: Additional keyword arguments, including "address_type".
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: str = cls.address_types[Avalanche.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Avalanche.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Avalanche.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: str = cls.address_types[kwargs.get("address_type")]

        prefix_got: str = address[:len(address_type)]
        if address_type != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {address_type}, got: {prefix_got})")
        address_no_prefix: str = address[len(address_type):]

        return CosmosAddress.decode(
            address=address_no_prefix, hrp=cls.hrp
        )
