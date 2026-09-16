#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..cryptocurrencies import Ripple
from .p2pkh import P2PKHAddress


class RippleAddress(P2PKHAddress):

    alphabet: str = Ripple.PARAMS.ALPHABET

    @staticmethod
    def name() -> str:
        """
        Return the name of the cryptocurrency, which is "Ripple".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Ripple"
