#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json

from hdwallet.cli.__main__ import cli_main


def test_cli_entropy(data, cli_tester):

    for client in data["entropies"].keys():
        for strength in data["entropies"][client].keys():
            cli = cli_tester.invoke(
                cli_main, [
                    "generate", "entropy",
                    "--client", client,
                    "--strength", strength
                ]
            )

            output = json.loads(cli.output)
            assert cli.exit_code == 0

            assert output["client"] == client
            assert output["strength"] == int(strength)

            if client == "Electrum-V2":
                assert len(output["entropy"]) == len(data["entropies"][client][strength]["entropy-not-suitable"])
            else:
                assert len(output["entropy"]) == len(data["entropies"][client][strength]["entropy"])
