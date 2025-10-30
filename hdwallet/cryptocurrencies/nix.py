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
    PUBLIC_KEY_ADDRESS_PREFIX = 0x26
    SCRIPT_ADDRESS_PREFIX = 0x35
    HRP = "nix"
    WITNESS_VERSIONS = WitnessVersions({
        "P2WPKH": 0x00,
        "P2WSH": 0x00
    })
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e
    })
    MESSAGE_PREFIX = "\x18Nix Signed Message:\n"
    WIF_PREFIX = 0x80


class NIX(ICryptocurrency):

    NAME = "NIX"
    SYMBOL = "NIX"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/NixPlatform/NixCore",
        "WHITEPAPER": "https://nixplatform.io/about/documentation",
        "WEBSITES": [
            "https://nixplatform.io",
            "https://governance.nixplatform.io"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.NIX
    SUPPORT_BIP38 = True
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
    SEEDS = Seeds((
        "BIP39", "SLIP39"
    ))
    HDS = HDs({
        "BIP32", "BIP44"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses((
        "P2PKH", "P2SH", "P2WPKH", {"P2WPKH_IN_P2SH": "P2WPKH-In-P2SH"}
    ))
    DEFAULT_ADDRESS = ADDRESSES.P2PKH
    SEMANTICS = [
        "p2pkh", "p2sh", "p2wpkh", "p2wpkh-in-p2sh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
