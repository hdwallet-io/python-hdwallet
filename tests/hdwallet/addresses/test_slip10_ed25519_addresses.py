#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.addresses.algorand import AlgorandAddress
from hdwallet.addresses.aptos import AptosAddress
from hdwallet.addresses.multiversx import MultiversXAddress
from hdwallet.addresses.near import NearAddress
from hdwallet.addresses.solana import SolanaAddress
from hdwallet.addresses.stellar import StellarAddress
from hdwallet.addresses.tezos import TezosAddress
from hdwallet.addresses.sui import SuiAddress


def test_algorand_address(data):

    assert AlgorandAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Algorand"]["name"]
    assert AlgorandAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Algorand"]["encode"]

    assert AlgorandAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Algorand"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Algorand"]["decode"]


def test_multiversx_address(data):

    assert MultiversXAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["MultiversX"]["name"]
    assert MultiversXAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["MultiversX"]["encode"]

    assert MultiversXAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["MultiversX"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["MultiversX"]["decode"]


def test_solana_address(data):

    assert SolanaAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Solana"]["name"]
    assert SolanaAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Solana"]["encode"]

    assert SolanaAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Solana"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Solana"]["decode"]


def test_stellar_address(data):

    assert StellarAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Stellar"]["name"]
    assert StellarAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Stellar"]["encode"]

    assert StellarAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Stellar"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Stellar"]["decode"]


def test_tezos_address(data):

    assert TezosAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Tezos"]["name"]
    assert TezosAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Tezos"]["encode"]

    assert TezosAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Tezos"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Tezos"]["decode"]


def test_sui_address(data):

    assert SuiAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Sui"]["name"]
    assert SuiAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Sui"]["encode"]

    assert SuiAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Sui"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Sui"]["decode"]


def test_aptos_address(data):

    assert AptosAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Aptos"]["name"]
    assert AptosAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Aptos"]["encode"]

    assert AptosAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Aptos"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Aptos"]["decode"]


def test_near_address(data):

    assert NearAddress.name() == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Near"]["name"]
    assert NearAddress.encode(
        public_key=data["addresses"]["SLIP10-Ed25519"]["public-key"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Near"]["encode"]

    assert NearAddress.decode(
        address=data["addresses"]["SLIP10-Ed25519"]["addresses"]["Near"]["encode"]
    ) == data["addresses"]["SLIP10-Ed25519"]["addresses"]["Near"]["decode"]
