#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from tabulate import tabulate

import click

from ...mnemonics import MNEMONICS


def list_languages():

    for index, mnemonic in enumerate(MNEMONICS.classes()):

        languages: list = []
        for _language in mnemonic.languages:
            language: str = ""
            for index, _ in enumerate(_language.split("-")):
                language += _.title() if index == 0 else f"-{_.title()}"
            languages.append([language])

        click.echo(tabulate(
            languages,
            [
                f"{mnemonic.name()} Languages"
            ],
            stralign="left",
            numalign="left"
        ))
        if index != (len(MNEMONICS.classes()) - 1):
            click.echo("\n")
