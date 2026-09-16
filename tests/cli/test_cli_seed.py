#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json

from hdwallet.cli.__main__ import cli_main


def test_cli_seed(data, cli_tester):

    for client in data["seeds"].keys():
        for words in data["seeds"][client].keys():
            if client == "Electrum-V2":
                for mnemonic_type in data["seeds"][client][words].keys():
                    for language in data["seeds"][client][words][mnemonic_type].keys():
                        cli_args = [
                                "generate", "seed",
                                "--client", client,
                                "--mnemonic-type", mnemonic_type,
                                "--mnemonic", data["seeds"][client][words][mnemonic_type][language]["mnemonic"]
                            ]

                        if data["seeds"][client][words][mnemonic_type][language]["passphrases"] != None:
                            cli_args.append("--passphrase")
                            cli_args.append("hdwallet")
                            seed = data["seeds"][client][words][mnemonic_type][language]["passphrases"]["hdwallet"]
                        else:
                            seed = data["seeds"][client][words][mnemonic_type][language]["non-passphrase-seed"]

                        cli = cli_tester.invoke(
                            cli_main, cli_args
                        )
                        output = json.loads(cli.output)

                        assert output["client"] == client
                        assert output["seed"] == seed
            elif client == "Cardano":
                for cardano_type in data["seeds"][client][words].keys():
                    for language in data["seeds"][client][words][cardano_type].keys():
                        cli_args = [
                                "generate", "seed",
                                "--client", client,
                                "--cardano-type", cardano_type,
                                "--mnemonic", data["seeds"][client][words][cardano_type][language]["mnemonic"]
                            ]

                        if data["seeds"][client][words][cardano_type][language]["passphrases"] != None:
                            cli_args.append("--passphrase")
                            cli_args.append("hdwallet")
                            seed = data["seeds"][client][words][cardano_type][language]["passphrases"]["hdwallet"]
                        else:
                            seed = data["seeds"][client][words][cardano_type][language]["non-passphrase-seed"]

                        cli = cli_tester.invoke(
                            cli_main, cli_args
                        )
                        output = json.loads(cli.output)

                        assert output["client"] == client
                        assert output["seed"] == seed
            else:
                for language in data["seeds"][client][words].keys():
                    cli_args = [
                            "generate", "seed",
                            "--client", client,
                            "--mnemonic", data["seeds"][client][words][language]["mnemonic"]
                        ]

                    if data["seeds"][client][words][language]["passphrases"] != None:
                        cli_args.append("--passphrase")
                        cli_args.append("hdwallet")
                        seed = data["seeds"][client][words][language]["passphrases"]["hdwallet"]
                    else:
                        seed = data["seeds"][client][words][language]["non-passphrase-seed"]

                    cli = cli_tester.invoke(
                        cli_main, cli_args
                    )
                    output = json.loads(cli.output)

                    assert output["client"] == client
                    assert output["seed"] == seed