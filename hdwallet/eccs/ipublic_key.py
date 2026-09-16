#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from __future__ import annotations

from typing import Any
from abc import (
    ABC, abstractmethod
)

from .ipoint import IPoint


class IPublicKey(ABC):

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
    def from_bytes(cls, public_key: bytes) -> "IPublicKey":
        """
        Create an IPublicKey instance from a byte representation.

        :param public_key: The byte sequence representing the public key.
        :type public_key: bytes

        :return: A new IPublicKey instance initialized from the byte representation.
        :rtype: IPublicKey
        """

    @classmethod
    @abstractmethod
    def from_point(cls, point: IPoint) -> "IPublicKey":
        """
        Create an IPublicKey instance from an IPoint.

        :param point: The IPoint instance to create the IPublicKey from.
        :type point: IPoint

        :return: An IPublicKey instance created from the given IPoint.
        :rtype: IPublicKey
        """

    @abstractmethod
    def raw_compressed(self) -> bytes:
        """
        Get the compressed raw byte representation of the object.

        :return: The compressed raw byte representation of the object.
        :rtype: bytes
        """

    @abstractmethod
    def raw_uncompressed(self) -> bytes:
        """
        Get the uncompressed raw byte representation of the object.

        :return: The uncompressed raw byte representation of the object.
        :rtype: bytes
        """

    @abstractmethod
    def point(self) -> IPoint:
        """
        Get the point representation of this object.

        :return: The IPoint representation of this object.
        :rtype: IPoint
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
    def compressed_length() -> int:
        """
        Get the compressed length of the object's data.

        :return: The length of the compressed data representation.
        :rtype: int
        """

    @staticmethod
    @abstractmethod
    def uncompressed_length() -> int:
        """
        Get the uncompressed length of the object's data.

        :return: The length of the uncompressed data representation.
        :rtype: int
        """

    @classmethod
    def is_valid_bytes(cls, public_key: bytes) -> bool:
        """
        Checks if the given bytes represent a valid bytes.

        :param public_key: The byte array to be validated.
        :type public_key: bytes

        :return: True if the byte array represents a valid public key, False otherwise.
        :rtype: bool
        """

        try:
            cls.from_bytes(public_key)
            return True
        except ValueError:
            return False

    @classmethod
    def is_valid_point(cls, point: IPoint) -> bool:
        """
        Checks if the given point is a valid point.

        :param point: The point to be validated.
        :type point: IPoint

        :return: True if the point is valid, False otherwise.
        :rtype: bool
        """

        try:
            cls.from_point(point)
            return True
        except ValueError:
            return False
