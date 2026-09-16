#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from .ientropy import IEntropy


class ALGORAND_ENTROPY_STRENGTHS:
    """
    Constants representing the entropy strengths for Algorand.
    """

    TWO_HUNDRED_FIFTY_SIX: int = 256


class AlgorandEntropy(IEntropy):
    """
    Uses entropy to generate a mnemonic phrase specific to Algorand,
    ensuring secure account creation with a unique checksum for
    address verification.

    .. note::
        This class inherits from the ``IEntropy`` class, thereby ensuring that all functions are accessible.

    Here are available ``ALGORAND_ENTROPY_STRENGTHS``:

    +-----------------------+-------+
    | Name                  | Value |
    +=======================+=======+
    | TWO_HUNDRED_FIFTY_SIX | 256   |
    +-----------------------+-------+
    """

    strengths = [
        ALGORAND_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    ]

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the entropy class.

        :return: The name of the entropy class.
        :rtype: str
        """

        return "Algorand"
