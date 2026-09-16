#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from __future__ import annotations

from typing import Any
from abc import (
    ABC, abstractmethod
)


class IPoint(ABC):

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
    def from_bytes(cls, point: bytes) -> "IPoint":
        """
        Create an IPoint instance from a byte representation.

        :param point: The byte sequence representing the point.
        :type point: bytes

        :return: A new IPoint instance initialized from the byte representation.
        :rtype: IPoint
        """

    @classmethod
    @abstractmethod
    def from_coordinates(cls, x: int, y: int) -> "IPoint":
        """
        Create an IPoint instance from x and y coordinates.

        :param x: The x-coordinate.
        :type x: int
        :param y: The y-coordinate.
        :type y: int

        :return: A new IPoint instance initialized with the given coordinates.
        :rtype: IPoint
        """

    @abstractmethod
    def x(self) -> int:
        """
        Get the x-coordinate value of the point.

        :return: The x-coordinate value.
        :rtype: int
        """

    @abstractmethod
    def y(self) -> int:
        """
        Get the y-coordinate value of the point.

        :return: The y-coordinate value.
        :rtype: int
        """

    def raw(self) -> bytes:
        """
        Get the raw byte representation of the object.

        :return: The raw byte representation of the object.
        :rtype: bytes
        """
        return self.raw_encoded()

    @abstractmethod
    def raw_encoded(self) -> bytes:
        """
        Get the encoded raw byte representation of the object.

        :return: The encoded raw byte representation of the object.
        :rtype: bytes
        """

    @abstractmethod
    def raw_decoded(self) -> bytes:
        """
        Get the decoded raw byte representation of the object.

        :return: The decoded raw byte representation of the object.
        :rtype: bytes
        """

    @abstractmethod
    def underlying_object(self) -> Any:
        """
        Get the underlying object represented by this instance.

        :return: The underlying object represented by this instance.
        :rtype: Any
        """

    @abstractmethod
    def __add__(self, point: "IPoint") -> "IPoint":
        """
        Add another point to this point.

        :param point: The point to add to this point.
        :type point: IPoint

        :return: A new instance of IPoint representing the sum of the points.
        :rtype: IPoint
        """

    @abstractmethod
    def __radd__(self, point: "IPoint") -> "IPoint":
        """
        Add this point to another point on the right-hand side.

        :param point: The point to which this point is added.
        :type point: IPoint

        :return: A new instance of IPoint representing the sum of the points.
        :rtype: IPoint
        """

    @abstractmethod
    def __mul__(self, scalar: int) -> 'IPoint':
        """
        Multiply this point by a scalar.

        :param scalar: The scalar integer to multiply this point by.
        :type scalar: int

        :return: A new instance of IPoint representing the result of the multiplication.
        :rtype: IPoint
        """

    @abstractmethod
    def __rmul__(self, scalar: int) -> 'IPoint':
        """
        Multiply a scalar by this point on the right-hand side.

        :param scalar: The scalar integer to multiply by this point.
        :type scalar: int

        :return: A new instance of IPoint representing the result of the multiplication.
        :rtype: IPoint
        """
