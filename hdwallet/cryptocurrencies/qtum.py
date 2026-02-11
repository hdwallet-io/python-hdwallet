#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Secp256k1ECC
from ..consts import (
    Info, WitnessVersions, Entropies, Mnemonics, Seeds, HDs, Addresses, Networks, XPrivateKeyVersions, XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Mainnet(INetwork):

    NAME = "mainnet"
    SCRIPT_ADDRESS_PREFIX = 0x32
    PUBLIC_KEY_ADDRESS_PREFIX = 0x3a
    HRP = "qc1"
    WITNESS_VERSIONS = WitnessVersions({
        "P2TR": 0x01,
        "P2WPKH": 0x00,
        "P2WSH": 0x00
    })
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })
    MESSAGE_PREFIX = None
    WIF_PREFIX = 0x80


class Testnet(INetwork):

    NAME = "testnet"
    SCRIPT_ADDRESS_PREFIX = 0x6e
    PUBLIC_KEY_ADDRESS_PREFIX = 0x78
    HRP = "tq1"
    WITNESS_VERSIONS = WitnessVersions({
        "P2TR": 0x01,
        "P2WPKH": 0x00,
        "P2WSH": 0x00
    })
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28,
        "P2WSH": 0x02575048,
        "P2WSH_IN_P2SH": 0x024285b5
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262,
        "P2WSH": 0x02575483,
        "P2WSH_IN_P2SH": 0x024289ef
    })
    MESSAGE_PREFIX = None
    WIF_PREFIX = 0xef


class Qtum(ICryptocurrency):

    NAME = "Qtum"
    SYMBOL = "QTUM"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/qtumproject/qtum",
        "WHITEPAPER": "https://qtumorg.s3.ap-northeast-2.amazonaws.com/Qtum_New_Whitepaper_en.pdf",
        "WEBSITES": [
            "https://qtum.org",
            "https://qtum.info"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.Qtum
    SUPPORT_BIP38 = True
    NETWORKS = Networks({
        "MAINNET": Mainnet, "TESTNET": Testnet
    })
    DEFAULT_NETWORK = NETWORKS.MAINNET
    ENTROPIES = Entropies({
        "BIP39"
    })
    MNEMONICS = Mnemonics({
        "BIP39",
    })
    SEEDS = Seeds((
        "BIP39", "SLIP39"
    ))
    HDS = HDs({
        "BIP32", "BIP44", "BIP49", "BIP84", "BIP86", "BIP141"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses((
        "P2PKH", "P2SH", "P2TR", "P2WPKH", {"P2WPKH_IN_P2SH": "P2WPKH-In-P2SH"}, "P2WSH", {"P2WSH_IN_P2SH": "P2WSH-In-P2SH"}
    ))
    DEFAULT_ADDRESS = ADDRESSES.P2PKH
    SEMANTICS = [
        "p2pkh", "p2sh", "p2wpkh", "p2wpkh-in-p2sh", "p2wsh", "p2wsh-in-p2sh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
