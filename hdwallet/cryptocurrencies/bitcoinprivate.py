#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Secp256k1ECC
from ..consts import (
    Info, Entropies, Mnemonics, Seeds, HDs, Addresses, Networks, XPrivateKeyVersions, XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    PUBLIC_KEY_ADDRESS_PREFIX = 0x1325
    SCRIPT_ADDRESS_PREFIX = 0x13af
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e
    })
    MESSAGE_PREFIX = "\x18BitcoinPrivate Signed Message:\n"
    WIF_PREFIX = 0x80


class Testnet(INetwork):

    NAME = "testnet"
    PUBLIC_KEY_ADDRESS_PREFIX = 0x1957
    SCRIPT_ADDRESS_PREFIX = 0x19e0
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf
    })
    MESSAGE_PREFIX = "\x18BitcoinPrivate Signed Message:\n"
    WIF_PREFIX = 0xef


class BitcoinPrivate(ICryptocurrency):

    NAME = "Bitcoin-Private"
    SYMBOL = "BTCP"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/BTCPrivate/BitcoinPrivate",
        "WHITEPAPER": "https://btcprivate.org/whitepaper.pdf",
        "WEBSITES": [
            "https://btcprivate.org"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.BitcoinPrivate
    SUPPORT_BIP38 = True
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
        "P2PKH", "P2SH"
    })
    DEFAULT_ADDRESS = ADDRESSES.P2PKH
    SEMANTICS = [
        "p2pkh", "p2sh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
