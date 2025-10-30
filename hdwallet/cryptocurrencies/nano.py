#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Ed25519Blake2bECC
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


class Nano(ICryptocurrency):

    NAME = "Nano"
    SYMBOL = "XNO"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/nanocurrency/nano-node",
        "WHITEPAPER": "https://nano.org/en/whitepaper",
        "WEBSITES": [
            "http://nano.org/en"
        ]
    })
    ECC = SLIP10Ed25519Blake2bECC
    COIN_TYPE = CoinTypes.Nano
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
    SEEDS = Seeds((
        "BIP39", "SLIP39"
    ))
    HDS = HDs({
        "BIP32", "BIP44"
    })
    DEFAULT_HD = HDS.BIP44
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    ADDRESSES = Addresses({
        "NANO": "Nano"
    })
    DEFAULT_ADDRESS = ADDRESSES.NANO
    SEMANTICS = [
        "p2pkh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    PARAMS = Params({
        "ADDRESS_PREFIX": "nano_",
        "ALPHABET": "13456789abcdefghijkmnopqrstuwxyz",
        "PAYLOAD_PADDING_DECODED": b"\x00\x00\x00",
        "PAYLOAD_PADDING_ENCODED": "1111"
    })
