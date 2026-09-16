#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..cryptocurrencies import Harmony
from .okt_chain import OKTChainAddress


class HarmonyAddress(OKTChainAddress):

    hrp: str = Harmony.NETWORKS.MAINNET.HRP

    @staticmethod
    def name() -> str:
        """
        Returns the name of the blockchain.

        :return: The name of the blockchain.
        :rtype: str
        """

        return "Harmony"
