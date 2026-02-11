#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Ed25519MoneroECC
from ..consts import (
    Info, Entropies, Mnemonics, Seeds, HDs, Addresses, AddressTypes, Networks, Params
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    STANDARD = 0x12
    INTEGRATED = 0x13
    SUB_ADDRESS = 0x2a


class Stagenet(INetwork):

    NAME = "stagenet"
    STANDARD = 0x18
    INTEGRATED = 0x19
    SUB_ADDRESS = 0x24


class Testnet(INetwork):

    NAME = "testnet"
    STANDARD = 0x35
    INTEGRATED = 0x36
    SUB_ADDRESS = 0x3f


class Monero(ICryptocurrency):

    NAME = "Monero"
    SYMBOL = "XMR"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/monero-project/monero",
        "WHITEPAPER": "https://github.com/monero-project/research-lab/blob/master/whitepaper/whitepaper.pdf",
        "WEBSITES": [
            "https://www.getmonero.org"
        ]
    })
    ECC = SLIP10Ed25519MoneroECC
    COIN_TYPE = CoinTypes.Monero
    SUPPORT_BIP38 = False
    NETWORKS = Networks({
        "MAINNET": Mainnet, "STAGENET": Stagenet, "TESTNET": Testnet
    })
    DEFAULT_NETWORK = NETWORKS.MAINNET
    ENTROPIES = Entropies((
        {"MONERO": "Monero"}, "BIP39"
    ))
    MNEMONICS = Mnemonics((
        {"MONERO": "Monero"}, "BIP39"
    ))
    SEEDS = Seeds((
        {"MONERO": "Monero"}, "BIP39", "SLIP39"
    ))
    HDS = HDs({
        "MONERO": "Monero"
    })
    DEFAULT_HD = HDS.MONERO
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses({
        "MONERO": "Monero"
    })
    DEFAULT_ADDRESS = ADDRESSES.MONERO
    ADDRESS_TYPES = AddressTypes({
        "STANDARD": "standard",
        "INTEGRATED": "integrated",
        "SUB_ADDRESS": "sub-address"
    })
    DEFAULT_ADDRESS_TYPE = ADDRESS_TYPES.STANDARD
    PARAMS = Params({
        "CHECKSUM_LENGTH": 4,
        "PAYMENT_ID_LENGTH": 8
    })
