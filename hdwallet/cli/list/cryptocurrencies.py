#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from tabulate import tabulate

import click

from ...cryptocurrencies import CRYPTOCURRENCIES


def list_cryptocurrencies():

    documents, table, headers = [], [], [
        "Cryptocurrency", "Symbol", "Coin Type", "Networks", "ECC"
    ]

    for cryptocurrency in CRYPTOCURRENCIES.classes():

        document: dict = {
            "name": cryptocurrency.NAME,
            "symbol": cryptocurrency.SYMBOL,
            "coin_type": cryptocurrency.COIN_TYPE,
            "networks": ", ".join(cryptocurrency.NETWORKS.get_networks()),
            "ecc": cryptocurrency.ECC.NAME
        }
        documents.append(document)

    for document in documents:
        table.append([
            document["name"],
            document["symbol"],
            document["coin_type"],
            document["networks"],
            document["ecc"],
        ])

    click.echo(tabulate(
        table,
        headers,
        colalign=(
            "left", "center", "center", "center", "center"
        )
    ))
