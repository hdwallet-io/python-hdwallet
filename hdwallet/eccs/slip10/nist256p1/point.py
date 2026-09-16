#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa.ecdsa import curve_256
from ecdsa.ellipticcurve import (
    Point, PointJacobi
)
from ecdsa import keys

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import IPoint
from ....utils import (
    bytes_to_integer, integer_to_bytes
)


class SLIP10Nist256p1Point(IPoint):

    point: PointJacobi

    def __init__(self, point: PointJacobi) -> None:
        """
        Initialize the point object.

        :param point: The PointJacobi object representing the point.
        :type point: PointJacobi
        """

        self.point = point

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Nist256p1"

    @classmethod
    def from_bytes(cls, point: bytes) -> IPoint:
        """
        Create an instance of SLIP10Nist256p1Point from bytes encoding.

        :param point: The bytes encoding the point coordinates.
        :type point: bytes

        :return: An instance of SLIP10Nist256p1Point representing the decoded point.
        :rtype: SLIP10Nist256p1Point
        """

        try:
            return cls(
                PointJacobi.from_bytes(
                    curve_256, point
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid point key bytes") from ex
        except AttributeError:
            return cls.from_coordinates(
                bytes_to_integer(point[:SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH]),
                bytes_to_integer(point[SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH:])
            )

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> IPoint:
        """
        Create an instance of SLIP10Nist256p1Point from x and y coordinates.

        :param x: The x-coordinate of the point.
        :type x: int

        :param y: The y-coordinate of the point.
        :type y: int

        :return: An instance of SLIP10Nist256p1Point representing the specified coordinates.
        :rtype: SLIP10Nist256p1Point
        """

        return cls(
            PointJacobi.from_affine(
                Point(curve_256, x, y)
            )
        )

    def underlying_object(self) -> Any:
        """
        Retrieve the underlying elliptic curve point object.

        This method returns the underlying elliptic curve point object
        represented by this instance.

        :return: The underlying elliptic curve point object.
        :rtype: Any
        """

        return self.point

    def x(self) -> int:
        """
        Get the x-coordinate of the elliptic curve point.

        :return: The x-coordinate of the elliptic curve point.
        :rtype: int
        """

        return self.point.x()

    def y(self) -> int:
        """
        Get the y-coordinate of the elliptic curve point.

        :return: The y-coordinate of the elliptic curve point.
        :rtype: int
        """

        return self.point.y()

    def raw_encoded(self) -> bytes:
        """
        Get the encoded bytes representation of the point.

        :return: Encoded bytes representation of the elliptic curve point.
        :rtype: bytes
        """

        try:
            return self.point.to_bytes("compressed")
        except AttributeError:
            x_bytes = integer_to_bytes(self.point.x(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)
            if self.point.y() & 1:
                enc_bytes = b"\x03" + x_bytes
            else:
                enc_bytes = b"\x02" + x_bytes
            return enc_bytes

    def raw_decoded(self) -> bytes:
        """
        Get the decoded bytes representation of the point.

        :return: Decoded bytes representation of the elliptic curve point.
        :rtype: bytes
        """

        try:
            return self.point.to_bytes()
        except AttributeError:
            x_bytes = integer_to_bytes(self.point.x(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)
            y_bytes = integer_to_bytes(self.point.y(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)

            return x_bytes + y_bytes

    def __add__(self, point: IPoint) -> IPoint:
        """
        Perform addition with another point on the elliptic curve.

        :param point: Another point to add to the current point.
        :type point: IPoint

        :return: A new instance of the same class representing the resulting
                 point after addition.
        :rtype: IPoint
        """

        return self.__class__(self.point + point.underlying_object())

    def __radd__(self, point: IPoint) -> IPoint:
        """
        Perform right addition with another point on the elliptic curve.

        :param point: Another point to add to the current point.
        :type point: IPoint

        :return: A new instance of the same class representing the resulting
                 point after addition.
        :rtype: IPoint
        """

        return self + point

    def __mul__(self, scalar: int) -> IPoint:
        """
        Perform scalar multiplication of the point on the curve.

        :param scalar: The scalar integer to multiply the point by.
        :type scalar: int

        :return: A new instance of the same class representing the resulting
                 point after scalar multiplication.
        :rtype: IPoint
        """

        return self.__class__(self.point * scalar)

    def __rmul__(self, scalar: int) -> IPoint:
        """
        Perform scalar multiplication in the reverse order.

        :param scalar: The scalar integer to multiply the point by.
        :type scalar: int

        :return: The resulting point after scalar multiplication.
        :rtype: IPoint
        """

        return self * scalar
