#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import List

from ..slip44 import CoinTypes
from ..eccs import KholawEd25519ECC
from ..consts import (
    Info, NestedNamespace, Entropies, Mnemonics, Seeds, HDs, Addresses, AddressTypes, Networks, Params, XPrivateKeyVersions, XPublicKeyVersions
)
from .icryptocurrency import (
    ICryptocurrency, INetwork
)


class Types(NestedNamespace):

    BYRON_ICARUS: str
    BYRON_LEDGER: str
    BYRON_LEGACY: str
    SHELLEY_ICARUS: str
    SHELLEY_LEDGER: str

    def get_cardano_types(self) -> List[str]:
        return list(self.__dict__.values())

    def is_cardano_type(self, cardano_type) -> bool:
        return cardano_type in self.get_cardano_types()


class Mainnet(INetwork):

    NAME = "mainnet"
    TYPE = 1
    PAYMENT_ADDRESS_HRP = "addr"
    REWARD_ADDRESS_HRP = "stake"
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x0f4331d4
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x0488b21e
    })


class Testnet(INetwork):

    NAME = "testnet"
    TYPE = 0
    PAYMENT_ADDRESS_HRP = "addr_test"
    REWARD_ADDRESS_HRP = "stake_test"
    XPRIVATE_KEY_VERSIONS = XPrivateKeyVersions({
        "P2PKH": 0x04358394
    })
    XPUBLIC_KEY_VERSIONS = XPublicKeyVersions({
        "P2PKH": 0x043587cf
    })


class Cardano(ICryptocurrency):

    NAME = "Cardano"
    SYMBOL = "ADA"
    INFO = Info({
        "SOURCE_CODE": "https://cardanoupdates.com",
        "WHITEPAPER": "https://docs.cardano.org/en/latest",
        "WEBSITES": [
            "https://www.cardano.org"
        ]
    })
    ECC = KholawEd25519ECC
    COIN_TYPE = CoinTypes.Cardano
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
        "CARDANO": "Cardano"
    })
    HDS = HDs({
        "CARDANO": "Cardano"
    })
    DEFAULT_HD = HDS.CARDANO
    DEFAULT_PATH = f"m/44'/{COIN_TYPE}'/0'/0/0"
    TYPES = Types({
        "BYRON_ICARUS": "byron-icarus",
        "BYRON_LEDGER": "byron-ledger",
        "BYRON_LEGACY": "byron-legacy",
        "SHELLEY_ICARUS": "shelley-icarus",
        "SHELLEY_LEDGER": "shelley-ledger"
    })
    ADDRESSES = Addresses({
        "CARDANO": "Cardano"
    })
    DEFAULT_ADDRESS = ADDRESSES.CARDANO
    SEMANTICS = [
        "p2pkh"
    ]
    DEFAULT_SEMANTIC = "p2pkh"
    ADDRESS_TYPES = AddressTypes({
        "PUBLIC_KEY": "public-key",
        "REDEMPTION": "redemption",
        "PAYMENT": "payment",
        "STAKING": "staking",
        "REWARD": "reward"
    })
    PARAMS = Params({
        "PUBLIC_KEY_ADDRESS": 0,
        "REDEMPTION_ADDRESS": 2,
        "PAYMENT_PREFIX": 0x00,
        "REWARD_PREFIX": 0x0e
    })
