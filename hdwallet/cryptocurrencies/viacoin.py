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
    PUBLIC_KEY_ADDRESS_PREFIX = 0x47
    SCRIPT_ADDRESS_PREFIX = 0x21
    HRP = "via"
    WITNESS_VERSIONS = WitnessVersions({
        "P2WPKH": 0x00,
        "P2WSH": 0x00
    })
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x0488ade4,
        "P2WPKH_IN_P2SH": 0x0488ade4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x0488b21e,
        "P2WPKH_IN_P2SH": 0x0488b21e
    })
    MESSAGE_PREFIX = "\x18Viacoin Signed Message:\n"
    WIF_PREFIX = 0xc7


class Testnet(INetwork):

    NAME = "testnet"
    PUBLIC_KEY_ADDRESS_PREFIX = 0x7f
    SCRIPT_ADDRESS_PREFIX = 0xc4
    HRP = "tvia"
    WITNESS_VERSIONS = WitnessVersions({
        "P2WPKH": 0x00,
        "P2WSH": 0x00
    })
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262
    })
    MESSAGE_PREFIX = "\x18Viacoin Signed Message:\n"
    WIF_PREFIX = 0xff


class Viacoin(ICryptocurrency):

    NAME = "Viacoin"
    SYMBOL = "VIA"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/viacoin/viacoin",
        "WHITEPAPER": "https://github.com/viacoin/documents/blob/master/whitepapers/Viacoin_fullcolor_whitepaper.pdf",
        "WEBSITES": [
            "http://viacoin.org"
        ]
    })
    ECC = SLIP10Secp256k1ECC
    COIN_TYPE = CoinTypes.Viacoin
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
    ADDRESSES = Addresses((
        "P2PKH", "P2SH", "P2WPKH", {"P2WPKH_IN_P2SH": "P2WPKH-In-P2SH"}
    ))
    DEFAULT_ADDRESS = ADDRESSES.P2PKH
    SEMANTICS = [
        "p2pkh", "p2sh", "p2wpkh", "p2wpkh-in-p2sh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
