#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from .ientropy import IEntropy


class SLIP39_ENTROPY_STRENGTHS:
    """
    Constants representing the entropy strengths for SLIP39.
    """
    ONE_HUNDRED_TWENTY_EIGHT: int = 128
    TWO_HUNDRED_FIFTY_SIX: int = 256
    FIVE_HUNDRED_TWELVE: int = 512


class SLIP39Entropy(IEntropy):
    """Stores entropy for SLIP-39. This data is used directly to create deterministic keys for
    various cryptocurrencies.

    .. note::
        This class inherits from the ``IEntropy`` class, thereby ensuring that all functions are accessible.

    Here are available ``SLIP39_ENTROPY_STRENGTHS``:

    +--------------------------+-------+
    | Name                     | Value |
    +==========================+=======+
    | ONE_HUNDRED_TWENTY_EIGHT |  128  |
    +--------------------------+-------+
    | TWO_HUNDRED_FIFTY_SIX    |  256  |
    +--------------------------+-------+
    | FIVE_HUNDRED_TWELVE      |  512  |
    +--------------------------+-------+

    """

    strengths = [
        SLIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        SLIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX,
        SLIP39_ENTROPY_STRENGTHS.FIVE_HUNDRED_TWELVE
    ]

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the entropy class.

        :return: The name of the entropy class.
        :rtype: str
        """

        return "SLIP39"
