#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from __future__ import annotations

from typing import Any
from abc import (
    ABC, abstractmethod
)

from .ipublic_key import IPublicKey


class IPrivateKey(ABC):

    @staticmethod
    @abstractmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

    @classmethod
    @abstractmethod
    def from_bytes(cls, private_key: bytes) -> "IPrivateKey":
        """
        Create an IPrivateKey instance from a byte representation.

        :param private_key: The byte sequence representing the private key.
        :type private_key: bytes

        :return: A new IPrivateKey instance initialized from the byte representation.
        :rtype: IPrivateKey
        """

    @abstractmethod
    def raw(self) -> bytes:
        """
        Get the raw byte representation of the object.

        :return: The raw byte representation of the object.
        :rtype: bytes
        """

    @abstractmethod
    def public_key(self) -> IPublicKey:
        """
        Get the public key represented by this object.

        :return: The IPublicKey representation of the public key.
        :rtype: IPublicKey
        """

    @abstractmethod
    def underlying_object(self) -> Any:
        """
        Retrieve the underlying object represented by this instance.

        :return: The underlying object represented by this instance.
        :rtype: Any
        """

    @staticmethod
    @abstractmethod
    def length() -> int:
        """
        Get the length of the object.

        :return: The length of the object.
        :rtype: int
        """

    @classmethod
    def is_valid_bytes(cls, private_key: bytes) -> bool:
        """
        Checks if the given point is a valid bytes.

        :param private_key: The bytes to be validated.
        :type private_key: bytes

        :return: True if the point is valid, False otherwise.
        :rtype: bool
        """

        try:
            cls.from_bytes(private_key)
            return True
        except ValueError:
            return False
