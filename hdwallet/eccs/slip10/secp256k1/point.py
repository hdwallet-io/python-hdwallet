#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Any
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.ellipticcurve import (
    Point, PointJacobi
)
from ecdsa import keys

import coincurve

from ....consts import SLIP10_SECP256K1_CONST
from ...iecc import IPoint
from ....utils import (
    bytes_to_integer, integer_to_bytes
)


class SLIP10Secp256k1PointCoincurve(IPoint):

    public_key: coincurve.PublicKey

    def __init__(self, public_key: coincurve.PublicKey) -> None:
        """
        Initialize the SLIP10Secp256k1PublicKey instance with a given public key.

        :param public_key: The public key object representing a Secp256k1 public key.
        :type public_key: coincurve.PublicKey

        :return: None
        """

        self.public_key = public_key

    @staticmethod
    def name() -> str:
        """
        Returns the name of the ecc class.

        :return: The name of the class.
        :rtype: str
        """

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, point_bytes: bytes) -> IPoint:
        """
        Creates a point object from bytes.

        :param cls: The class object.
        :type cls: Type
        :param point_bytes: The bytes representing the point.
        :type point_bytes: bytes

        :return: A point object created from the provided bytes.
        :rtype: IPoint
        """

        if len(point_bytes) == SLIP10_SECP256K1_CONST.PUBLIC_KEY_UNCOMPRESSED_BYTE_LENGTH - 1:
            return cls(coincurve.PublicKey(SLIP10_SECP256K1_CONST.PUBLIC_KEY_UNCOMPRESSED_PREFIX + point_bytes))
        if len(point_bytes) == SLIP10_SECP256K1_CONST.PUBLIC_KEY_COMPRESSED_BYTE_LENGTH:
            return cls(coincurve.PublicKey(point_bytes))
        raise ValueError("Invalid point bytes")

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> IPoint:
        """
        Creates a point object from x and y coordinates.

        :param cls: The class object.
        :type cls: Type
        :param x: The x-coordinate of the point.
        :type x: int
        :param y: The y-coordinate of the point.
        :type y: int

        :return: A point object representing the coordinates (x, y).
        :rtype: IPoint
        """

        try:
            return cls(coincurve.PublicKey.from_point(x, y))
        except ValueError as ex:
            raise ValueError("Invalid point coordinates") from ex

    def underlying_object(self) -> Any:
        """
        Returns the underlying public key object.

        :return: The underlying public key object.
        :rtype: Any
        """

        return self.public_key

    def x(self) -> int:
        """
        Returns the x of the point.

        :return: The x of the point.
        :rtype: int
        """

        return self.public_key.point()[0]

    def y(self) -> int:
        """
        Returns the y of the point.

        :return: The y of the point.
        :rtype: int
        """

        return self.public_key.point()[1]

    def raw_encoded(self) -> bytes:
        """
        Returns the encoded raw bytes representation of the public key, including any necessary prefix.

        :return: The encoded raw bytes of the public key.
        :rtype: bytes
        """

        return self.public_key.format(True)

    def raw_decoded(self) -> bytes:
        """
        Returns the decoded raw bytes representation of the public key, excluding any prefix.

        :return: The decoded raw bytes of the public key.
        :rtype: bytes
        """

        return self.public_key.format(False)[1:]

    def __add__(self, point: IPoint) -> IPoint:
        """
        Adds another point to the current public key point using elliptic curve point addition.

        :param point: The other point to add to the current point.
        :type point: IPoint

        :return: A new instance of the class with the resulting point after addition.
        :rtype: IPoint
        """

        return self.__class__(self.public_key.combine([point.underlying_object()]))

    def __radd__(self, point: IPoint) -> IPoint:
        """
        Adds the current public key point to another point using elliptic curve point addition.
        This method allows addition in reverse order, i.e., point + self.

        :param point: The other point to add to the current point.
        :type point: IPoint

        :return: A new instance of the class with the resulting point after addition.
        :rtype: IPoint
        """

        return self + point

    def __mul__(self, scalar: int) -> IPoint:
        """
        Multiplies the current public key point by a scalar using elliptic curve scalar multiplication.

        :param scalar: The scalar integer to multiply the point with.
        :type scalar: int

        :return: A new instance of the class with the resulting point after multiplication.
        :rtype: IPoint
        """

        bytes_num = None or ((scalar.bit_length() if scalar > 0 else 1) + 7) // 8
        return self.__class__(self.public_key.multiply(scalar.to_bytes(bytes_num, byteorder="big", signed=False)))

    def __rmul__(self, scalar: int) -> IPoint:
        """
        Performs scalar multiplication of the point.

        :param scalar: The scalar integer by which to multiply the point.
        :type scalar: int

        :return: Resulting point after scalar multiplication.
        :rtype: IPoint

        """

        return self * scalar


class SLIP10Secp256k1PointECDSA(IPoint):

    point: PointJacobi

    def __init__(self, point_obj: PointJacobi) -> None:
        """
        Initializes the class with a PointJacobi object.

        :param point_obj: The PointJacobi object representing the point.
        :type point_obj: PointJacobi
        """

        self.point = point_obj

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Secp256k1"

    @classmethod
    def from_bytes(cls, point_bytes: bytes) -> IPoint:
        """
        Creates a point from its byte representation.

        :param point_bytes: The byte representation of the point.
        :type point_bytes: bytes

        :return: An instance of IPoint representing the decoded point.
        :rtype: IPoint
        """

        try:
            return cls(
                PointJacobi.from_bytes(
                    curve_secp256k1, point_bytes
                )
            )
        except keys.MalformedPointError as ex:
            raise ValueError("Invalid point key bytes") from ex
        except AttributeError:
            return cls.from_coordinates(
                bytes_to_integer(point_bytes[:SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH]),
                bytes_to_integer(point_bytes[SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH:])
            )

    @classmethod
    def from_coordinates(cls, x: int, y: int) -> IPoint:
        """
        Creates a point from x and y.

        :param x: The x of the point.
        :type x: int
        :param y: The y of the point.
        :type y: int

        :return: An instance of IPoint representing the point with the given coordinates.
        :rtype: IPoint
        """

        return cls(
            PointJacobi.from_affine(
                Point(curve_secp256k1, x, y)
            )
        )

    def underlying_object(self) -> Any:
        """
        Returns the underlying point object.

        :return: The underlying point object.
        :rtype: Any
        """

        return self.point

    def x(self) -> int:
        """
        Returns the x of the point.

        :return: The x of the point.
        :rtype: int
        """

        return self.point.x()

    def y(self) -> int:
        """
        Returns the y of the point.

        :return: The y of the point.
        :rtype: int
        """

        return self.point.y()

    def raw_encoded(self) -> bytes:
        """
        Returns the raw encoded bytes of the point.

        :return: The raw encoded bytes of the point.
        :rtype: bytes
        """

        try:
            return self.point.to_bytes("compressed")
        except AttributeError:
            x: bytes = integer_to_bytes(self.point.x(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)
            return b"\x03" + x if self.point.y() & 1 else b"\x02" + x

    def raw_decoded(self) -> bytes:
        """
        Returns the raw decoded bytes of the point.

        :return: The raw bytes of the point.
        :rtype: bytes
        """

        try:
            return self.point.to_bytes()
        except AttributeError:
            x: bytes = integer_to_bytes(self.point.x(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)
            y: bytes = integer_to_bytes(self.point.y(), SLIP10_SECP256K1_CONST.POINT_COORDINATE_BYTE_LENGTH)

            return x + y

    def __add__(self, point: IPoint) -> IPoint:
        """
        Performs addition with another point.

        :param point: The point to add.
        :type point: IPoint

        :return: A new instance of the class representing the result of the addition.
        :rtype: IPoint
        """

        return self.__class__(self.point + point.underlying_object())

    def __radd__(self, point: IPoint) -> IPoint:
        """
        Performs addition with another point in the context of scalar multiplication.

        :param point: The point to add (right operand).
        :type point: IPoint

        :return: A new instance of the class representing the result of the addition.
        :rtype: IPoint
        """

        return self + point

    def __mul__(self, scalar: int) -> IPoint:
        """
        Performs scalar multiplication on the point.

        :param scalar: The scalar value to multiply with the point.
        :type scalar: int

        :return: A new instance of the class representing the result of scalar multiplication.
        :rtype: IPoint
        """

        return self.__class__(self.point * scalar)

    def __rmul__(self, scalar: int) -> IPoint:
        """
        Performs scalar multiplication on the point.

        :param scalar: The scalar value to multiply with the point.
        :type scalar: int

        :return: The result of scalar multiplication.
        :rtype: IPoint
        """

        return self * scalar


if SLIP10_SECP256K1_CONST.USE == "coincurve":
    SLIP10Secp256k1Point = SLIP10Secp256k1PointCoincurve
elif SLIP10_SECP256K1_CONST.USE == "ecdsa":
    SLIP10Secp256k1Point = SLIP10Secp256k1PointECDSA
else:
    raise Exception(
        f"Invalid SLIP10-Secp256k1 use, (expected: 'coincurve' or 'ecdsa', got: '{SLIP10_SECP256K1_CONST.USE}')"
    )
