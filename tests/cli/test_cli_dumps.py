#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from os import path

import json
import copy
import pytest

from hdwallet.cli.__main__ import cli_main
from dump_rules import rules

def unpack_dumps(): 
    all_data = []

    file_path = path.abspath(
        path.join(path.dirname(__file__), 
        "../data/json/hdwallet.json")
    )
    values = open(file_path, "r", encoding="utf-8")
    hdw_data = json.loads(values.read())
    values.close()

    for hd in rules.keys():
        for key in hdw_data[hd].keys():
            if key == "derivation": 
                continue
            if hd == "Monero" and key == "from-private-key":
                continue
            else: 
                all_data.append((
                    hdw_data[hd][key],
                    hdw_data[hd]["derivation"],
                    hd,
                    key
                ))
    return all_data


def get_derivation_args(derivation):
    args = [
        "--derivation",
        derivation["name"]
    ]

    for k, v in derivation["args"].items():
        args.extend([
            f"--{k}", v
        ])

    return args


def get_hd_args(dumps, args):
    args_ls = []
    for k, v in args.items():
        if isinstance(v, tuple):
            arg = v[0]
        else:
            arg = dumps[v]
            if k == 'language':
                arg = arg.lower()

        args_ls.extend([
            f"--{k}", arg
        ])
    return args_ls


def get_dumps_output(ddict):
    root_keys = {k: v for k, v in ddict.items() if k != "derivations"}
    ret = f"{json.dumps(root_keys, indent=4, ensure_ascii=False)}\n"

    for d in ddict.get("derivations", []):
        ret += f"{json.dumps(d, indent=4, ensure_ascii=False)}\n"

    return ret

@pytest.mark.parametrize(
    "hd_data",
    unpack_dumps(),
    ids=lambda data: "{}, {}".format(data[2], data[3])
)
def test_cli_dumps(cli_tester, hd_data):

    dumps, derivation, hd, name = hd_data
    hd_args = get_hd_args(dumps, rules[hd]["args"])
    for param, rule in rules[hd]["available-methods"].items():
        final_dumps = copy.deepcopy(dumps)
        args = [
            "dumps",
            "--format", "json",
            "--symbol", dumps["symbol"],
            "--hd", hd
        ]
        args.extend(hd_args)

        if name in ["byron-icarus", "byron-ledger", "byron-legacy"]:
            args.extend(["--address-type", "public-key"])
        elif name in ["shelley-icarus", "shelley-ledger"]:
            args.extend(["--address-type", "staking"])

        if rule["derivable"]:
            args.extend(get_derivation_args(derivation))
            args.extend([
                f"--{param}", dumps[rule["method"]]
            ])
        else:
            args.extend([
                f"--{param}", dumps["derivations"][-1][rule["method"]]
            ])

        if "root-changes" in rule:
            final_dumps.update(rule["root-changes"])
        if "derivation-changes" in rule:
            for derivation in final_dumps["derivations"]:
                derivation.update(rule["derivation-changes"])

        cli = cli_tester.invoke(cli_main, args)

        assert cli.exit_code == 0
        if rule["derivable"]:
            assert cli.output == get_dumps_output(final_dumps)
        else:
            assert cli.output.strip() == ""

        args[0] = "dump"
        args.remove("--format")
        args.remove("json")

        final_dumps["derivation"] = final_dumps["derivations"][-1]

        if not rule["derivable"] and "at" in final_dumps["derivation"]:
            del final_dumps["derivation"]["at"]
        
        del final_dumps["derivations"]

        cli = cli_tester.invoke(cli_main, args)
        assert cli.exit_code == 0
        assert json.loads(cli.output) == final_dumps
