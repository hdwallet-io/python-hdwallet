#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..cryptocurrencies import XinFin
from .ethereum import EthereumAddress


class XinFinAddress(EthereumAddress):

    address_prefix: str = XinFin.PARAMS.ADDRESS_PREFIX

    @staticmethod
    def name() -> str:
        """
        Return the name associated with the XinFin blockchain.

        :return: The name "XinFin".
        :rtype: str
        """

        return "XinFin"
