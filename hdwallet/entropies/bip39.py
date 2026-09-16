#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from .ientropy import IEntropy


class BIP39_ENTROPY_STRENGTHS:
    """
    Constants representing the entropy strengths for BIP39.
    """
    ONE_HUNDRED_TWENTY_EIGHT: int = 128
    ONE_HUNDRED_SIXTY: int = 160
    ONE_HUNDRED_NINETY_TWO: int = 192
    TWO_HUNDRED_TWENTY_FOUR: int = 224
    TWO_HUNDRED_FIFTY_SIX: int = 256


class BIP39Entropy(IEntropy):
    """
    Converts entropy into a mnemonic phrase (12, 15, 18, 21, or 24 words). This phrase is used to
    derive a seed, which creates deterministic keys for various cryptocurrencies.

    .. note::
        This class inherits from the ``IEntropy`` class, thereby ensuring that all functions are accessible.

    Here are available ``BIP39_ENTROPY_STRENGTHS``:

    +--------------------------+-------+
    | Name                     | Value |
    +==========================+=======+
    | ONE_HUNDRED_TWENTY_EIGHT |  128  |
    +--------------------------+-------+
    | ONE_HUNDRED_SIXTY        |  160  |
    +--------------------------+-------+
    | ONE_HUNDRED_NINETY_TWO   |  192  |
    +--------------------------+-------+
    | TWO_HUNDRED_TWENTY_FOUR  |  224  |
    +--------------------------+-------+
    | TWO_HUNDRED_FIFTY_SIX    |  256  |
    +--------------------------+-------+
    """

    strengths = [
        BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_SIXTY,
        BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_NINETY_TWO,
        BIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_TWENTY_FOUR,
        BIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    ]

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the entropy class.

        :return: The name of the entropy class.
        :rtype: str
        """

        return "BIP39"
