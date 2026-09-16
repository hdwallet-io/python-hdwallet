#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from .....consts import SLIP10_ED25519_CONST
from ....iecc import IPoint
from .. import SLIP10Ed25519PublicKey
from .point import SLIP10Ed25519MoneroPoint


class SLIP10Ed25519MoneroPublicKey(SLIP10Ed25519PublicKey):

    @staticmethod
    def name() -> str:
        """
        Get the name of the ecc class.

        :return: The name of the ecc class.
        :rtype: str
        """

        return "SLIP10-Ed25519-Monero"

    @staticmethod
    def compressed_length() -> int:
        """
        Returns the compressed length of the Ed25519 Monero public key.

        :return: The compressed length of the Ed25519 Monero public key.
        :rtype: int
        """

        return SLIP10_ED25519_CONST.PUBLIC_KEY_BYTE_LENGTH

    @staticmethod
    def uncompressed_length() -> int:
        """
        Returns the uncompressed length of the Ed25519 Monero public key.

        :return: The uncompressed length of the Ed25519 Monero public key.
        :rtype: int
        """

        return SLIP10Ed25519MoneroPublicKey.compressed_length()

    def raw_compressed(self) -> bytes:
        """
        Retrieves the raw compressed public key bytes.

        :return: The raw compressed public key bytes.
        :rtype: bytes
        """

        return bytes(self.verify_key)

    def raw_uncompressed(self) -> bytes:
        """
        Retrieves the raw uncompressed public key bytes.

        :return: The raw compressed public key bytes.
        :rtype: bytes
        """

        return self.raw_compressed()

    def point(self) -> IPoint:
        """
        Retrieves the point on the elliptic curve corresponding to the public key.

        :return: The elliptic curve point corresponding to the public key.
        :rtype: IPoint
        """

        return SLIP10Ed25519MoneroPoint(bytes(self.verify_key))
