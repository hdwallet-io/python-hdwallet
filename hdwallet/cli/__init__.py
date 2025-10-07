#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit
import inspect
from bip38 import cryptocurrencies

BIP38_CRYPTOCURRENCIES = {
    name: cls for name, cls in inspect.getmembers(cryptocurrencies, inspect.isclass)
    if issubclass(cls, cryptocurrencies.ICryptocurrency)
}
