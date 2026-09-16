#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from tabulate import tabulate

import click

from ...entropies import ENTROPIES


def list_strengths():

    for index, entropy in enumerate(ENTROPIES.classes()):

        strengths: list = []
        for strength in entropy.strengths:
            strengths.append([strength])

        click.echo(tabulate(
            strengths,
            [
                f"{entropy.name()} Strengths"
            ],
            stralign="left",
            numalign="left"
        ))
        if index != (len(ENTROPIES.classes()) - 1):
            click.echo("\n")
