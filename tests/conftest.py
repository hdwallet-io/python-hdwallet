#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from click.testing import CliRunner

import os
import json
import pytest

@pytest.fixture(scope="session", name="data")
def load_test_data():
    base_path = os.path.dirname(__file__)
    jsons = os.listdir(os.path.join(base_path, f"data/json/"))
    data = {}

    for json_file in jsons:
        file_path = os.path.join(base_path, f"data/json/{json_file}")
        with open(file_path, "r", encoding="utf-8") as values:
            test_data_name = json_file.split(".")[0]
            data[test_data_name] = json.load(values)
    return data


@pytest.fixture(scope="module")
def cli_tester():
    return CliRunner()
