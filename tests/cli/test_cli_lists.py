#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from os import path

from hdwallet.cli.__main__ import cli_main


def test_cryptocurrencies_list(cli_tester):
    cli = cli_tester.invoke(
        cli_main, [
            "list", "c",
        ]
    )

    assert cli.exit_code == 0

    file_path = path.abspath(
        path.join(path.dirname(__file__), 
        "../data/raw/cryptocurrencies.txt")
    )

    with open(file_path, "r") as values:
        assert cli.output.strip() == values.read().strip()

def test_languages_list(cli_tester):
    cli = cli_tester.invoke(
        cli_main, [
            "list", "l",
        ]
    )

    assert cli.exit_code == 0

    file_path = path.abspath(
        path.join(path.dirname(__file__), 
        "../data/raw/languages.txt")
    )

    with open(file_path, "r") as values:
        assert cli.output.strip() == values.read().strip()


def test_strengths_list(cli_tester):
    cli = cli_tester.invoke(
        cli_main, [
            "list", "s",
        ]
    )

    assert cli.exit_code == 0

    file_path = path.abspath(
        path.join(path.dirname(__file__), 
        "../data/raw/strengths.txt")
    )

    with open(file_path, "r") as values:
        assert cli.output.strip() == values.read().strip()

