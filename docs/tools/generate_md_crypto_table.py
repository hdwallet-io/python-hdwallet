# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
from hdwallet.cryptocurrencies import (
    CRYPTOCURRENCIES, ICryptocurrency
)

def _joined(arr):
    return ", ".join(f"`{i}`" for i in arr)

def get_source_link(c):
    if hasattr(c.INFO, "SOURCE_CODE"):
        return getattr(c.INFO, "SOURCE_CODE")
    if hasattr(c.INFO, "WEBSITES"):
        return getattr(c.INFO, "WEBSITES")[0]
    return "#"

cryptocurrencies: ICryptocurrency = CRYPTOCURRENCIES.classes()

check_right: str = ":white_check_mark:"
check_x: str = ":x:"

headers = ["Name", "Symbol", "Coin Type", "Networks", "ECC", "HDs", "BIP38", "Addresses"]
data = [
    [
        f"[{c.NAME}]({get_source_link(c)})",#c.NAME,
        c.SYMBOL,
        c.COIN_TYPE,
        _joined(c.NETWORKS.get_networks()),
        c.ECC.NAME,
        _joined(c.HDS.get_hds()),
        check_right if c.SUPPORT_BIP38 else check_x,
        _joined(c.ADDRESSES.get_addresses())
    ]
    for c in CRYPTOCURRENCIES.classes()
]

rows = [headers] + data
columns = list(zip(*rows))
col_widths = [max( [len(str(item)) for item in col] ) for col in columns]

def build_md_table():
    header = " | ".join(f"{header:<{w}}" for header, w in zip(headers, col_widths)) + " |"

    header_separator = [
        f":{'-' * w}" if i == 0 else f":{'-' * w}:"
        for i, w in enumerate(col_widths)
    ]
    separator = "|".join(header_separator) + "|"

    formatted_rows = [
        " | ".join(f"{cell:<{w}}" for cell, w in zip(row, col_widths)) + " |"
        for row in data
    ]
    return "\n".join([header, separator] + formatted_rows)

with open("output.md", "w") as md_file:
    md_file.write(build_md_table())