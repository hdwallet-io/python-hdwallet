#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from .ientropy import IEntropy


class MONERO_ENTROPY_STRENGTHS:
    """
    Constants for Monero entropy strengths.
    """

    ONE_HUNDRED_TWENTY_EIGHT: int = 128
    TWO_HUNDRED_FIFTY_SIX: int = 256


class MoneroEntropy(IEntropy):
    """
    Uses high entropy to generate a 25-word mnemonic seed, with the last word acting
    as a checksum. This ensures secure generation of private spend and view keys.

    .. note::
        This class inherits from the ``IEntropy`` class, thereby ensuring that all functions are accessible.

    Here are available ``MONERO_ENTROPY_STRENGTHS``:

    +--------------------------+-------+
    | Name                     | Value |
    +==========================+=======+
    | ONE_HUNDRED_TWENTY_EIGHT |  128  |
    +--------------------------+-------+
    | TWO_HUNDRED_FIFTY_SIX    |  256  |
    +--------------------------+-------+
    """

    strengths = [
        MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    ]

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the entropy class.

        :return: The name of the entropy class.
        :rtype: str
        """

        return "Monero"
