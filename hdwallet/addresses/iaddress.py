#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from __future__ import annotations

from abc import (
    ABC, abstractmethod
)
from typing import (
    Union
)

from ..eccs import IPublicKey


class IAddress(ABC):

    @staticmethod
    @abstractmethod
    def name() -> str:
        """
        Get the name of the address class.

        :return: The name of the address class.
        :rtype: str
        """

        pass

    @classmethod
    @abstractmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs) -> str:
        """
        Encodes the given public key into a address.

        :param public_key: The public key to encode. Can be bytes, string, or an object implementing IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
        :type kwargs: Any

        :return: The encoded address as a string.
        :rtype: str
        """

        pass

    @classmethod
    @abstractmethod
    def decode(cls, address: str, **kwargs) -> str:
        """
        Decodes the given address into its corresponding public key or public key hash.

        :param address: The address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments specific to each decoding type.
        :type kwargs: Any

        :return: The decoded public key as a string.
        :rtype: str
        """

        pass
