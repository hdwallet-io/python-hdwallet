#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Any
)

from ....libs.ed25519 import (
    point_add,
    int_encode,
    point_encode,
    point_is_encoded_bytes,
    point_is_generator,
    point_is_on_curve,
    point_is_decoded_bytes,
    point_coord_to_bytes,
    point_bytes_to_coord,
    point_scalar_mul_base,
    point_scalar_mul
)
from ...iecc import IPoint


class SLIP10Ed25519Point(IPoint):

    is_generator: bool
    point: bytes
    _x: Optional[int]
    _y: Optional[int]

    def __init__(self, point: bytes) -> None:
        """
        Initializes an instance with a byte representation of a point.

        :param point: The byte representation of the point.
        :type point: bytes
        """

        if not point_is_encoded_bytes(point):
            raise ValueError("Invalid point bytes")

        self.point = point
        self.is_generator = point_is_generator(point)
        self._x, self._y = None, None

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Ed25519"

    @classmethod
    def from_bytes(cls, point: bytes) -> IPoint:
        """
        Creates an instance of the Ed25519 point from its byte representation.

        :param point: The byte representation of the point.
        :type point: bytes

        :return: An instance of the Ed25519 point.
        :rtype: IPoint
        """

        if not point_is_on_curve(point):
            raise ValueError("Invalid point bytes")
        if point_is_decoded_bytes(point):
            point = point_encode(
                point_bytes_to_coord(point)
            )
        return cls(point)

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> IPoint:
        """
        Creates an instance of the Ed25519 point from x and y coordinates.

        :param x: The x-coordinate of the point.
        :type x: int

        :param y: The y-coordinate of the point.
        :type y: int

        :return: An instance of the Ed25519 point.
        :rtype: IPoint
        """

        return cls.from_bytes(
            point_coord_to_bytes((x, y))
        )

    def underlying_object(self) -> Any:
        """
        Returns the underlying object representing the Ed25519 Monero point.

        :return: The underlying object representing the Ed25519 Monero point.
        :rtype: Any
        """

        return self.point

    def x(self) -> int:
        """
        Returns the x-coordinate of the Ed25519 Monero public key point.

        :return: The x-coordinate of the Ed25519 Monero public key point.
        :rtype: int
        """

        if self._x is None:
            self._x, self._y = point_bytes_to_coord(self.point)
        return self._x

    def y(self) -> int:
        """
        Returns the y-coordinate of the Ed25519 point.

        :return: The y-coordinate of the Ed25519 point.
        :rtype: int
        """

        if self._y is None:
            self._x, self._y = point_bytes_to_coord(self.point)
        return self._y

    def raw_encoded(self) -> bytes:
        """
        Returns the raw encoded point data.

        :return: The raw encoded point as bytes.
        :rtype: bytes
        """

        return self.point

    def raw_decoded(self) -> bytes:
        """
        Returns the decoded raw bytes representation of the point coordinates.

        :return: The raw decoded bytes of the point coordinates.
        :rtype: bytes
        """

        return int_encode(self.x()) + int_encode(self.y())

    def __add__(self, point: IPoint) -> IPoint:
        """
        Performs addition of this point object with another point object (`point`).

        :param point: The other point object to add to `self`.
        :type point: IPoint

        :return: The resulting point after addition.
        :rtype: IPoint
        """

        return self.__class__(
            point_add(self.point, point.underlying_object())
        )

    def __radd__(self, point: IPoint) -> IPoint:
        """
        Performs addition of this point object with another point object (`point`).

        :param point: The other point object to add to `self`.
        :type point: IPoint

        :return: The resulting point after addition.
        :rtype: IPoint
        """

        return self + point

    def __mul__(self, scalar: int) -> IPoint:
        """
        Performs scalar multiplication of this point object with an integer scalar.

        :param scalar: The scalar integer to multiply the point by.
        :type scalar: int

        :return: The resulting point after scalar multiplication.
        :rtype: IPoint
        """

        if self.is_generator:
            return self.__class__(
                point_scalar_mul_base(scalar)
            )
        return self.__class__(
            point_scalar_mul(scalar, self.point)
        )

    def __rmul__(self, scalar: int) -> IPoint:
        """
        Performs scalar multiplication of this point object with an integer scalar.

        :param scalar: The scalar integer to multiply the point by.
        :type scalar: int

        :return: The resulting point after scalar multiplication.
        :rtype: IPoint
        """

        return self * scalar
