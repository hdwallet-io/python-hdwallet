#!/usr/bin/env python3

# Copyright © 2020-2026, Abenezer Lulseged Wube <itsm3abena@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Ed25519ECC
from ..consts import (
    Info, Entropies, Mnemonics, Seeds, HDs, Addresses, Networks, Params, XPrivateKeyVersions, XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x0488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x0488b21e
    })


class Ton(ICryptocurrency):

    NAME = "Ton"
    SYMBOL = "TON"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/ton-blockchain",
        "WHITEPAPER": "https://docs.ton.org/learn/docs",
        "WEBSITES": [
            "https://ton.org"
        ]
    })
    ECC = SLIP10Ed25519ECC
    COIN_TYPE = CoinTypes.Ton
    SUPPORT_BIP38 = False
    NETWORKS = Networks({
        "MAINNET": Mainnet
    })
    DEFAULT_NETWORK = NETWORKS.MAINNET
    ENTROPIES = Entropies({
        "BIP39"
    })
    MNEMONICS = Mnemonics({
        "BIP39"
    })
    SEEDS = Seeds({
        "BIP39"
    })
    HDS = HDs({
        "BIP32", "BIP44"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'"
    ADDRESSES = Addresses({
        "TON": "Ton"
    })
    DEFAULT_ADDRESS = ADDRESSES.TON
    SEMANTICS = [
        "p2pkh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    PARAMS = Params({
        "BOUNCEABLE_TAG": 0x11,
        "NON_BOUNCEABLE_TAG": 0x51,
        "TEST_FLAG": 0x80,
        "DEFAULT_BOUNCEABLE": False,
        "WORKCHAIN": 0,
        "WALLET_ID": 698983191,
        "DEFAULT_WALLET_VERSION": "v5r1",
        "MAINNET_NETWORK_GLOBAL_ID": -239,
        "TESTNET_NETWORK_GLOBAL_ID": -3,
        "SUBWALLET_NUMBER": 0
    })
