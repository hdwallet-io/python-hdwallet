#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Secp256k1ECC
from ..consts import (
    Info, Entropies, Mnemonics, Seeds, HDs, Addresses, AddressTypes, Networks, Params, XPrivateKeyVersions, XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    TYPE = 0x00
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x488b21e
    })
    WIF_PREFIX = 0x80


class Testnet(INetwork):

    NAME = "testnet"
    TYPE = 0x10
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x04358394
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x043587cf
    })
    WIF_PREFIX = 0xef


class Ergo(ICryptocurrency):

    NAME = "Ergo"
    SYMBOL = "ERG"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/ergoplatform/ergo",
        "WHITEPAPER": "https://ergoplatform.org/en/documents",
        "WEBSITES": [
            "https://ergoplatform.org"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.Ergo
    SUPPORT_BIP38 = False
    NETWORKS = Networks({
        "MAINNET": Mainnet, "TESTNET": Testnet
    })
    DEFAULT_NETWORK = NETWORKS.MAINNET
    ENTROPIES = Entropies({
        "BIP39"
    })
    MNEMONICS = Mnemonics({
        "BIP39"
    })
    SEEDS = Seeds((
        "BIP39", "SLIP39"
    ))
    HDS = HDs({
        "BIP32", "BIP44"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses({
        "ERGO": "Ergo"
    })
    DEFAULT_ADDRESS = ADDRESSES.ERGO
    SEMANTICS = [
        "p2pkh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    ADDRESS_TYPES = AddressTypes({
        "P2PKH": "p2pkh",
        "P2SH": "p2sh"
    })
    DEFAULT_ADDRESS_TYPE = ADDRESS_TYPES.P2PKH
    PARAMS = Params({
        "CHECKSUM_LENGTH": 4,
        "ADDRESS_TYPES": {
            "P2PKH": 0x01,  # Pay to Public Key Hash
            "P2SH": 0x02  # Pay to Script Hash
        }
    })
