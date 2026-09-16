# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import CRYPTOCURRENCIES

def _joined(arr):
    return " ".join(f"``{i}``" for i in arr)

def get_source_link(c):
    if hasattr(c.INFO, "SOURCE_CODE"):
        return c.INFO.SOURCE_CODE
    elif hasattr(c.INFO, "WEBSITES") and c.INFO.WEBSITES:
        return c.INFO.WEBSITES[0]
    else:
        return "#"

cryptocurrencies = CRYPTOCURRENCIES.classes()
check_right = "✅"
check_x = "❌"

headers = ["Name", "Symbol", "Coin Type", "Networks", "ECC", "HDs", "BIP38", "Addresses"]

def format_row(row):
    return "  * - " + str(row[0]) + ''.join("\n    - " + str(cell) for cell in row[1:])

def build_rst_table():
    lines = [
        ".. list-table::",
        "  :width: 100%",
        "  :header-rows: 1\n"
    ]
    lines.append(format_row(headers))
    for c in cryptocurrencies:
        row = [
            f"`{c.NAME} <{get_source_link(c)}>`_",
            c.SYMBOL,
            c.COIN_TYPE,
            _joined(c.NETWORKS.get_networks()),
            c.ECC.NAME,
            _joined(c.HDS.get_hds()),
            check_right if c.SUPPORT_BIP38 else check_x,
            _joined(c.ADDRESSES.get_addresses())
        ]
        lines.append(format_row(row))
    return '\n'.join(lines)

with open("output.rst", "w", encoding="utf-8") as rst_file:
    rst_file.write(build_rst_table())
