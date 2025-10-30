#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from ..slip44 import CoinTypes
from ..eccs import SLIP10Ed25519ECC
from ..consts import (
    Info, Entropies, Mnemonics, Seeds, HDs, Addresses, AddressTypes, Networks, Params, XPrivateKeyVersions, XPublicKeyVersions
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


class PiNetwork(ICryptocurrency):

    NAME = "Pi-Network"
    SYMBOL = "PI"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/pi-apps",
        "WHITEPAPER": "https://minepi.com/white-paper",
        "WEBSITES": [
            "https://minepi.com"
        ]
    })
    ECC = SLIP10Ed25519ECC
    COIN_TYPE = CoinTypes.PiNetwork
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
        "STELLAR": "Stellar"
    })
    DEFAULT_ADDRESS = ADDRESSES.STELLAR
    SEMANTICS = [
        "p2pkh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    ADDRESS_TYPES = AddressTypes({
        "PRIVATE_KEY": "private_key",
        "PUBLIC_KEY": "public_key"
    })
    DEFAULT_ADDRESS_TYPE = ADDRESS_TYPES.PUBLIC_KEY
    PARAMS = Params({
        "CHECKSUM_LENGTH": 2,
        "ADDRESS_TYPES": {
            "PRIVATE_KEY": 18 << 3,
            "PUBLIC_KEY": 6 << 3
        }
    })
