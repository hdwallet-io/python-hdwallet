#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Secp256k1ECC
from ..consts import (
    Info, WitnessVersions, Entropies, Mnemonics, Seeds, HDs, Addresses, AddressTypes, Networks, XPrivateKeyVersions,
    XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    LEGACY_PUBLIC_KEY_ADDRESS_PREFIX = 0x00
    LEGACY_SCRIPT_ADDRESS_PREFIX = 0x05
    STD_PUBLIC_KEY_ADDRESS_PREFIX = 0x00
    STD_SCRIPT_ADDRESS_PREFIX = 0x08
    HRP = "ecash"
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e
    })
    WIF_PREFIX = 0x80


class Testnet(INetwork):

    NAME = "testnet"
    LEGACY_PUBLIC_KEY_ADDRESS_PREFIX = 0x6f
    LEGACY_SCRIPT_ADDRESS_PREFIX = 0xc4
    STD_PUBLIC_KEY_ADDRESS_PREFIX = 0x00
    STD_SCRIPT_ADDRESS_PREFIX = 0x08
    HRP = "ectest"
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf
    })
    WIF_PREFIX = 0xef


class eCash(ICryptocurrency):

    NAME = "eCash"
    SYMBOL = "XEC"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/bitcoin-abc",
        "WEBSITES": [
            "https://e.cash"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.eCash
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
    SEEDS = Seeds({
        "BIP39"
    })
    HDS = HDs({
        "BIP32", "BIP44"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses((
        {"BITCOINCASH": "BitcoinCash"}, "P2PKH", "P2SH"
    ))
    DEFAULT_ADDRESS = ADDRESSES.P2PKH
    SEMANTICS = [
        "p2pkh", "p2sh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    ADDRESS_TYPES = AddressTypes({
        "STD": "std",
        "LEGACY": "legacy"
    })
    DEFAULT_ADDRESS_TYPE = ADDRESS_TYPES.STD
