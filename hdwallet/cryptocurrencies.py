#!/usr/bin/env python3

from types import SimpleNamespace
from typing import Any, Optional

import inspect
import sys


class NestedNamespace(SimpleNamespace):
    def __init__(self, dictionary, **kwargs):
        super().__init__(**kwargs)
        for key, value in dictionary.items():
            if isinstance(value, dict):
                self.__setattr__(key, NestedNamespace(value))
            else:
                self.__setattr__(key, value)


class SegwitAddress(NestedNamespace):

    HRP: Optional[str] = None
    VERSION: int = 0x00


class CoinType(NestedNamespace):

    INDEX: int
    HARDENED: bool
    
    def __str__(self):
        return f"{self.INDEX}'" if self.HARDENED else f"{self.INDEX}"


class ExtendedKey(NestedNamespace):

    P2PKH: int
    P2SH: int

    P2WPKH: Optional[int] = None
    P2WPKH_IN_P2SH: Optional[int] = None

    P2WSH: Optional[int] = None
    P2WSH_IN_P2SH: Optional[int] = None


class ExtendedPrivateKey(ExtendedKey):

    pass


class ExtendedPublicKey(ExtendedKey):

    pass


class Cryptocurrency(NestedNamespace):

    NAME: str
    SYMBOL: str
    NETWORK: str
    SOURCE_CODE: Optional[str]
    COIN_TYPE: CoinType

    SCRIPT_ADDRESS: int
    PUBLIC_KEY_ADDRESS: int
    SEGWIT_ADDRESS: SegwitAddress

    EXTENDED_PRIVATE_KEY: ExtendedPrivateKey
    EXTENDED_PUBLIC_KEY: ExtendedPublicKey

    MESSAGE_PREFIX: Optional[str]
    DEFAULT_PATH: str
    WIF_SECRET_KEY: int


class AnonMainnet(Cryptocurrency):

    NAME = "Anon"
    SYMBOL = "ANON"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 220,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5389
    PUBLIC_KEY_ADDRESS = 0x582
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18ANON Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ArgoneumMainnet(Cryptocurrency):

    NAME = "Argoneum"
    SYMBOL = "AGM"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 421,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x61
    PUBLIC_KEY_ADDRESS = 0x32
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class ArtaxMainnet(Cryptocurrency):

    NAME = "Artax"
    SYMBOL = "XAX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 219,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x17
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Artax Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x97


class AryacoinMainnet(Cryptocurrency):

    NAME = "Aryacoin"
    SYMBOL = "AYA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 357,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x6f
    PUBLIC_KEY_ADDRESS = 0x17
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Aryacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x97


class AsiacoinMainnet(Cryptocurrency):

    NAME = "Asiacoin"
    SYMBOL = "AC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 51,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x17
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18AsiaCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x97


class AtomMainnet(Cryptocurrency):

    NAME = "Atom"
    SYMBOL = "ATOM"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 118,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xa
    PUBLIC_KEY_ADDRESS = 0x17
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "atom",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Atom Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class AuroracoinMainnet(Cryptocurrency):

    NAME = "Auroracoin"
    SYMBOL = "AUR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 85,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x17
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18AuroraCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x97


class AviancoinMainnet(Cryptocurrency):
    NAME = "Aviancoin"
    SYMBOL = "AVN"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/AvianNetwork/Avian"
    COIN_TYPE = CoinType({
        "INDEX": 921,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7a
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "av",
        "VERSION": 0x0d
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })
    
    MESSAGE_PREFIX = "Aviancoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class AxeMainnet(Cryptocurrency):

    NAME = "Axe"
    SYMBOL = "AXE"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 4242,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x10
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcc


class BataMainnet(Cryptocurrency):

    NAME = "Bata"
    SYMBOL = "BTA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 89,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xa40b91bd,
        "P2SH": 0xa40b91bd,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xa40c86fa,
        "P2SH": 0xa40c86fa,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bata Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa4


class BeetleCoinMainnet(Cryptocurrency):

    NAME = "Beetle Coin"
    SYMBOL = "BEET"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 800,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x1a
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Beetlecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class BelaCoinMainnet(Cryptocurrency):

    NAME = "Bela Coin"
    SYMBOL = "BELA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 73,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BelaCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class BitCloudMainnet(Cryptocurrency):

    NAME = "Bit Cloud"
    SYMBOL = "BTDX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 218,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BitCloud Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class BitSendMainnet(Cryptocurrency):

    NAME = "Bit Send"
    SYMBOL = "BSD"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 91,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x66
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitsend Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcc


class BitcoinCashMainnet(Cryptocurrency):

    NAME = "Bitcoin Cash"
    SYMBOL = "BCH"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bitcoincashorg/bitcoincash.org"
    COIN_TYPE = CoinType({
        "INDEX": 145,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x28
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BitcoinGoldMainnet(Cryptocurrency):

    NAME = "Bitcoin Gold"
    SYMBOL = "BTG"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/BTCGPU/BTCGPU"
    COIN_TYPE = CoinType({
        "INDEX": 156,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x17
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "btg",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = "\x1DBitcoin Gold Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BitcoinMainnet(Cryptocurrency):

    NAME = "Bitcoin"
    SYMBOL = "BTC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bitcoin/bitcoin"
    COIN_TYPE = CoinType({
        "INDEX": 0,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BitcoinPlusMainnet(Cryptocurrency):

    NAME = "Bitcoin Plus"
    SYMBOL = "XBC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 65,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BitcoinPlus Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class BitcoinSVMainnet(Cryptocurrency):

    NAME = "Bitcoin SV"
    SYMBOL = "BSV"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 236,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x0
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BitcoinTestnet(Cryptocurrency):

    NAME = "Bitcoin"
    SYMBOL = "BTCTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/bitcoin/bitcoin"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tb",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28,
        "P2WSH": 0x02575048,
        "P2WSH_IN_P2SH": 0x024285b5
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262,
        "P2WSH": 0x02575483,
        "P2WSH_IN_P2SH": 0x024289ef
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class BitcoinZMainnet(Cryptocurrency):

    NAME = "BitcoinZ"
    SYMBOL = "BTCZ"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 177,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x1cb8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BitcoinZ Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BitcoreMainnet(Cryptocurrency):

    NAME = "Bitcore"
    SYMBOL = "BTX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 160,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bitcore",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BitCore Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BlackcoinMainnet(Cryptocurrency):

    NAME = "Blackcoin"
    SYMBOL = "BLK"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 10,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x2cfbf60,
        "P2SH": 0x2cfbf60,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x2cfbede,
        "P2SH": 0x2cfbede,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BlackCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class BlockStampMainnet(Cryptocurrency):

    NAME = "Block Stamp"
    SYMBOL = "BST"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 254,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x0
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BlockStamp Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BlocknodeMainnet(Cryptocurrency):

    NAME = "Blocknode"
    SYMBOL = "BND"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 2941,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x3f
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Blocknode Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x4b


class BlocknodeTestnet(Cryptocurrency):

    NAME = "Blocknode"
    SYMBOL = "BNDTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x55
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Blocknode Testnet Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x89


class BolivarcoinMainnet(Cryptocurrency):

    NAME = "Bolivarcoin"
    SYMBOL = "BOLI"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 278,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x55
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "Bolivarcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xd5


class BritCoinMainnet(Cryptocurrency):

    NAME = "Brit Coin"
    SYMBOL = "BRIT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 70,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18BritCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class CPUChainMainnet(Cryptocurrency):

    NAME = "CPU Chain"
    SYMBOL = "CPU"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 363,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1e
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "cpu",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x1DCPUchain Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class CanadaECoinMainnet(Cryptocurrency):

    NAME = "Canada eCoin"
    SYMBOL = "CDN"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 34,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Canada eCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9c


class CannacoinMainnet(Cryptocurrency):

    NAME = "Cannacoin"
    SYMBOL = "CCN"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 19,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Cannacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9c


class ClamsMainnet(Cryptocurrency):

    NAME = "Clams"
    SYMBOL = "CLAM"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 23,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xd
    PUBLIC_KEY_ADDRESS = 0x89
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xa8c17826,
        "P2SH": 0xa8c17826,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xa8c26d64,
        "P2SH": 0xa8c26d64,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x85


class ClubCoinMainnet(Cryptocurrency):

    NAME = "Club Coin"
    SYMBOL = "CLUB"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 79,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18ClubCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class CompcoinMainnet(Cryptocurrency):

    NAME = "Compcoin"
    SYMBOL = "CMP"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 71,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18CompCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9c


class CranePayMainnet(Cryptocurrency):

    NAME = "Crane Pay"
    SYMBOL = "CRP"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 2304,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xa
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "cp",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x7b


class CraveMainnet(Cryptocurrency):

    NAME = "Crave"
    SYMBOL = "CRAVE"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 186,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x46
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18DarkNet Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x99


class DashMainnet(Cryptocurrency):

    NAME = "Dash"
    SYMBOL = "DASH"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/dashpay/dash"
    COIN_TYPE = CoinType({
        "INDEX": 5,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x10
    PUBLIC_KEY_ADDRESS = 0x4c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcc


class DashTestnet(Cryptocurrency):

    NAME = "Dash"
    SYMBOL = "DASHTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/dashpay/dash"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x13
    PUBLIC_KEY_ADDRESS = 0x8c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class DeepOnionMainnet(Cryptocurrency):

    NAME = "Deep Onion"
    SYMBOL = "ONION"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 305,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x4e
    PUBLIC_KEY_ADDRESS = 0x1f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "dpn",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18DeepOnion Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9f


class DefcoinMainnet(Cryptocurrency):

    NAME = "Defcoin"
    SYMBOL = "DFC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1337,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18defcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9e


class DenariusMainnet(Cryptocurrency):

    NAME = "Denarius"
    SYMBOL = "DNR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 116,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5a
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Denarius Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9e


class DiamondMainnet(Cryptocurrency):

    NAME = "Diamond"
    SYMBOL = "DMD"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 152,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x5a
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Diamond Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xda


class DigiByteMainnet(Cryptocurrency):

    NAME = "Digi Byte"
    SYMBOL = "DGB"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 20,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "dgb",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19DigiByte Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class DigitalcoinMainnet(Cryptocurrency):

    NAME = "Digitalcoin"
    SYMBOL = "DGC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 18,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x9e0488b2,
        "P2SH": 0x9e0488b2,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Digitalcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9e


class DogecoinMainnet(Cryptocurrency):

    NAME = "Dogecoin"
    SYMBOL = "DOGE"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/dogecoin/dogecoin"
    COIN_TYPE = CoinType({
        "INDEX": 3,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x16
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x02fac398,
        "P2SH": 0x02fac398,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x02facafd,
        "P2SH": 0x02facafd,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Dogecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xf1


class DogecoinTestnet(Cryptocurrency):

    NAME = "Dogecoin"
    SYMBOL = "DOGETEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/dogecoin/dogecoin"
    COIN_TYPE = CoinType({
        "INDEX": 3,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x71
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "dogecointestnet",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": 0x04358394,
        "P2WPKH_IN_P2SH": 0x04358394,
        "P2WSH": 0x04358394,
        "P2WSH_IN_P2SH": 0x04358394
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": 0x043587cf,
        "P2WPKH_IN_P2SH": 0x043587cf,
        "P2WSH": 0x043587cf,
        "P2WSH_IN_P2SH": 0x043587cf
    })

    MESSAGE_PREFIX = "\x19Dogecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xf1


class EDRCoinMainnet(Cryptocurrency):

    NAME = "EDR Coin"
    SYMBOL = "EDRC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 56,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x5d
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18EDRcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xdd


class EcoinMainnet(Cryptocurrency):

    NAME = "Ecoin"
    SYMBOL = "ECN"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 115,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x14
    PUBLIC_KEY_ADDRESS = 0x5c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18eCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xdc


class EinsteiniumMainnet(Cryptocurrency):

    NAME = "Einsteinium"
    SYMBOL = "EMC2"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 41,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Einsteinium Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa1


class ElastosMainnet(Cryptocurrency):

    NAME = "Elastos"
    SYMBOL = "ELA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 2305,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class EnergiMainnet(Cryptocurrency):

    NAME = "Energi"
    SYMBOL = "NRG"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 9797,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x35
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xd7dc6e9f,
        "P2SH": 0xd7dc6e9f,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x3b8c856,
        "P2SH": 0x3b8c856,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "DarkCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x6a


class EthereumMainnet(Cryptocurrency):

    NAME = "Ethereum"
    SYMBOL = "ETH"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/ethereum/go-ethereum"
    COIN_TYPE = CoinType({
        "INDEX": 60,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class BinanceSmartChainMainnet(Cryptocurrency):

    NAME = "Binance Smart Chain"
    SYMBOL = "BSC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bnb-chain/bsc"
    COIN_TYPE = CoinType({
        "INDEX": 9006,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class PolygonMainnet(Cryptocurrency):

    NAME = "Polygon"
    SYMBOL = "MATIC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bnb-chain/bsc"
    COIN_TYPE = CoinType({
        "INDEX": 966,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ArbitrumMainnet(Cryptocurrency):

    NAME = "Arbitrum"
    SYMBOL = "ARB1"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bnb-chain/bsc"
    COIN_TYPE = CoinType({
        "INDEX": 9001,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class zkSyncMainnet(Cryptocurrency):

    NAME = "zkSync"
    SYMBOL = "ZKS"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bnb-chain/bsc"
    COIN_TYPE = CoinType({
        "INDEX": 804,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class LineaMainnet(Cryptocurrency):

    NAME = "Linea"
    SYMBOL = "LINEA"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/bnb-chain/bsc"
    COIN_TYPE = CoinType({
        "INDEX": 59144,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class EuropeCoinMainnet(Cryptocurrency):

    NAME = "Europe Coin"
    SYMBOL = "ERC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 151,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa8


class EvrmoreMainnet(Cryptocurrency):

    NAME = "Evrmore"
    SYMBOL = "EVR"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/EvrmoreOrg/Evrmore"
    COIN_TYPE = CoinType({
        "INDEX": 175,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5c
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "ev",
        "VERSION": 0x0b
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })
    
    MESSAGE_PREFIX = "Evrmore Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class EvrmoreTestnet(Cryptocurrency):

    NAME = "Evrmore"
    SYMBOL = "EVRTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/EvrmoreOrg/Evrmore"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "te",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })
    
    MESSAGE_PREFIX = "Evrmore Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class ExclusiveCoinMainnet(Cryptocurrency):

    NAME = "Exclusive Coin"
    SYMBOL = "EXCL"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 190,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x89
    PUBLIC_KEY_ADDRESS = 0x21
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18ExclusiveCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa1


class FIXMainnet(Cryptocurrency):

    NAME = "FIX"
    SYMBOL = "FIX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 336,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5f
    PUBLIC_KEY_ADDRESS = 0x23
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x3c


class FIXTestnet(Cryptocurrency):

    NAME = "FIX"
    SYMBOL = "FIXTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x89
    PUBLIC_KEY_ADDRESS = 0x4c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x3a805837,
        "P2SH": 0x3a805837,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x3a8061a0,
        "P2SH": 0x3a8061a0,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xed


class FeathercoinMainnet(Cryptocurrency):

    NAME = "Feathercoin"
    SYMBOL = "FTC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 8,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0xe
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488daee,
        "P2SH": 0x488daee,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488bc26,
        "P2SH": 0x488bc26,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Feathercoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x8e


class FirstcoinMainnet(Cryptocurrency):

    NAME = "Firstcoin"
    SYMBOL = "FRST"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 167,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x23
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18FirstCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa3


class FlashcoinMainnet(Cryptocurrency):

    NAME = "Flashcoin"
    SYMBOL = "FLASH"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 120,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x82
    PUBLIC_KEY_ADDRESS = 0x44
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Flashcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc4

class FluxMainnet(Cryptocurrency):

    NAME = "Flux"
    SYMBOL = "FLUX"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/RunOnFlux/fluxd"
    COIN_TYPE = CoinType({
        "INDEX": 19167,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x1cb8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    MESSAGE_PREFIX = "\x18Zelcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class FoxdcoinMainnet(Cryptocurrency):

    NAME = "Foxdcoin"
    SYMBOL = "FOXD"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/foxdproject/foxdcoin"
    COIN_TYPE = CoinType({
        "INDEX": 175,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1e
    PUBLIC_KEY_ADDRESS = 0x23
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "fx",
        "VERSION": 0x0d
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = "Foxdcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class FoxdcoinTestnet(Cryptocurrency):

    NAME = "Foxdcoin"
    SYMBOL = "FOXDTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/foxdproject/foxdcoin"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5a
    PUBLIC_KEY_ADDRESS = 0x5f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tf",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })
    
    MESSAGE_PREFIX = "Foxdcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class FujiCoinMainnet(Cryptocurrency):

    NAME = "Fuji Coin"
    SYMBOL = "FJC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 75,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x10
    PUBLIC_KEY_ADDRESS = 0x24
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "fc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19FujiCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa4


class GCRCoinMainnet(Cryptocurrency):

    NAME = "GCR Coin"  # Global Currency Reserve Coin
    SYMBOL = "GCR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 49,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x61
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18GCR Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9a


class GameCreditsMainnet(Cryptocurrency):

    NAME = "Game Credits"
    SYMBOL = "GAME"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 101,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa6


class GoByteMainnet(Cryptocurrency):

    NAME = "Go Byte"
    SYMBOL = "GBX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 176,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xa
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18DarkCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc6


class GridcoinMainnet(Cryptocurrency):

    NAME = "Gridcoin"
    SYMBOL = "GRC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 84,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x3e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Gridcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbe


class GroestlCoinMainnet(Cryptocurrency):

    NAME = "Groestl Coin"
    SYMBOL = "GRS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 17,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x24
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "grs",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19GroestlCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class GroestlCoinTestnet(Cryptocurrency):

    NAME = "Groestl Coin"
    SYMBOL = "GRSTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tgrs",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19GroestlCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class GuldenMainnet(Cryptocurrency):

    NAME = "Gulden"
    SYMBOL = "NLG"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 87,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x62
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Guldencoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x62


class HushMainnet(Cryptocurrency):

    NAME = "Hush"
    SYMBOL = "HUSH"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 197,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x1cb8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Hush Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class HelleniccoinMainnet(Cryptocurrency):

    NAME = "Helleniccoin"
    SYMBOL = "HNC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 168,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x30
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18helleniccoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class HempcoinMainnet(Cryptocurrency):

    NAME = "Hempcoin"
    SYMBOL = "THC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 113,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x28
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Hempcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa8


class IXCoinMainnet(Cryptocurrency):

    NAME = "IX Coin"
    SYMBOL = "IXC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 86,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x8a
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Ixcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class InsaneCoinMainnet(Cryptocurrency):

    NAME = "Insane Coin"
    SYMBOL = "INSN"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 68,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x39
    PUBLIC_KEY_ADDRESS = 0x66
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18INSaNe Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x37


class InternetOfPeopleMainnet(Cryptocurrency):

    NAME = "Internet Of People"
    SYMBOL = "IOP"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 66,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xae
    PUBLIC_KEY_ADDRESS = 0x75
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xae3416f6,
        "P2SH": 0xae3416f6,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x2780915f,
        "P2SH": 0x2780915f,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18IoP Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x31


class JumbucksMainnet(Cryptocurrency):

    NAME = "Jumbucks"
    SYMBOL = "JBS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 26,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x2b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x37a6460,
        "P2SH": 0x37a6460,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x37a689a,
        "P2SH": 0x37a689a,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Jumbucks Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xab


class KobocoinMainnet(Cryptocurrency):

    NAME = "Kobocoin"
    SYMBOL = "KOBO"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 196,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x23
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Kobocoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xa3


class KomodoMainnet(Cryptocurrency):

    NAME = "Komodo"
    SYMBOL = "KMD"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 141,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Komodo Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbc


class LBRYCreditsMainnet(Cryptocurrency):

    NAME = "LBRY Credits"
    SYMBOL = "LBC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 140,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7a
    PUBLIC_KEY_ADDRESS = 0x55
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18LBRYcrd Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x1c


class LinxMainnet(Cryptocurrency):

    NAME = "Linx"
    SYMBOL = "LINX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 114,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x4b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18LinX Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcb


class LitecoinCashMainnet(Cryptocurrency):

    NAME = "Litecoin Cash"
    SYMBOL = "LCC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 192,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x1c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Litecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class LitecoinMainnet(Cryptocurrency):

    NAME = "Litecoin"
    SYMBOL = "LTC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/litecoin-project/litecoin"
    COIN_TYPE = CoinType({
        "INDEX": 2,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x32
    PUBLIC_KEY_ADDRESS = 0x30
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "ltc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Litecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class LitecoinTestnet(Cryptocurrency):

    NAME = "Litecoin"
    SYMBOL = "LTCTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/litecoin-project/litecoin"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x3a
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tltc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x19Litecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class LitecoinZMainnet(Cryptocurrency):

    NAME = "LitecoinZ"
    SYMBOL = "LTZ"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 221,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xab8
    PUBLIC_KEY_ADDRESS = 0xab3
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade3,
        "P2SH": 0x488ade3,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18LitecoinZ Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class LkrcoinMainnet(Cryptocurrency):

    NAME = "Lkrcoin"
    SYMBOL = "LKR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 557,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x30
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18LKRcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class LynxMainnet(Cryptocurrency):

    NAME = "Lynx"
    SYMBOL = "LYNX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 191,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x32
    PUBLIC_KEY_ADDRESS = 0x2d
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Lynx Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xad


class MazacoinMainnet(Cryptocurrency):

    NAME = "Mazacoin"
    SYMBOL = "MZC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 13,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x9
    PUBLIC_KEY_ADDRESS = 0x32
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xe0


class MegacoinMainnet(Cryptocurrency):

    NAME = "Megacoin"
    SYMBOL = "MEC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 217,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x32
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Megacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb2


class MinexcoinMainnet(Cryptocurrency):

    NAME = "Minexcoin"
    SYMBOL = "MNX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 182,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x4b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class MonacoinMainnet(Cryptocurrency):

    NAME = "Monacoin"
    SYMBOL = "MONA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 22,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x37
    PUBLIC_KEY_ADDRESS = 0x32
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "mona",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Monacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb0


class MonkeyProjectMainnet(Cryptocurrency):

    NAME = "Monkey Project"
    SYMBOL = "MONK"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 214,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x33
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "monkey",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488dde4,
        "P2SH": 0x488dde4,
        "P2WPKH": 0x488dde4,
        "P2WPKH_IN_P2SH": 0x488dde4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "Monkey Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x37


class MyriadcoinMainnet(Cryptocurrency):

    NAME = "Myriadcoin"
    SYMBOL = "XMY"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 90,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x9
    PUBLIC_KEY_ADDRESS = 0x32
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb2


class NIXMainnet(Cryptocurrency):

    NAME = "NIX"
    SYMBOL = "NIX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 400,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x35
    PUBLIC_KEY_ADDRESS = 0x26
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "nix",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x488ade4,
        "P2WPKH_IN_P2SH": 0x488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x488b21e,
        "P2WPKH_IN_P2SH": 0x488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Nix Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class NamecoinMainnet(Cryptocurrency):

    NAME = "Namecoin"
    SYMBOL = "NMC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 7,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xd
    PUBLIC_KEY_ADDRESS = 0x34
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class NavcoinMainnet(Cryptocurrency):

    NAME = "Navcoin"
    SYMBOL = "NAV"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/navcoin/navcoin-core"
    COIN_TYPE = CoinType({
        "INDEX": 130,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x35
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Navcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x96


class NeblioMainnet(Cryptocurrency):

    NAME = "Neblio"
    SYMBOL = "NEBL"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 146,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x70
    PUBLIC_KEY_ADDRESS = 0x35
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Neblio Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb5


class NeoscoinMainnet(Cryptocurrency):

    NAME = "Neoscoin"
    SYMBOL = "NEOS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 25,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x35
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18NeosCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb1


class NeurocoinMainnet(Cryptocurrency):

    NAME = "Neurocoin"
    SYMBOL = "NRO"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 110,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x75
    PUBLIC_KEY_ADDRESS = 0x35
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18PPCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb5


class NewYorkCoinMainnet(Cryptocurrency):

    NAME = "New York Coin"
    SYMBOL = "NYC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 179,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x16
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18newyorkc Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbc


class NovacoinMainnet(Cryptocurrency):

    NAME = "Novacoin"
    SYMBOL = "NVC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 50,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x14
    PUBLIC_KEY_ADDRESS = 0x8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18NovaCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x88


class NuBitsMainnet(Cryptocurrency):

    NAME = "NuBits"
    SYMBOL = "NBT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 12,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1a
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Nu Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x96


class NuSharesMainnet(Cryptocurrency):

    NAME = "NuShares"
    SYMBOL = "NSR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 11,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x40
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Nu Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x95


class OKCashMainnet(Cryptocurrency):

    NAME = "OK Cash"
    SYMBOL = "OK"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 69,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x3cc1c73,
        "P2SH": 0x3cc1c73,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x3cc23d7,
        "P2SH": 0x3cc23d7,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18OKCash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x3


class OmniMainnet(Cryptocurrency):

    NAME = "Omni"
    SYMBOL = "OMNI"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/omnilayer/omnicore"
    COIN_TYPE = CoinType({
        "INDEX": 200,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class OmniTestnet(Cryptocurrency):

    NAME = "Omni"
    SYMBOL = "OMNITEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/omnilayer/omnicore"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Bitcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class OnixCoinMainnet(Cryptocurrency):

    NAME = "Onix Coin"
    SYMBOL = "ONX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 174,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x4b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "ONIX Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcb


class PeercoinMainnet(Cryptocurrency):

    NAME = "Peercoin"
    SYMBOL = "PPC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 6,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x75
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb7


class PesobitMainnet(Cryptocurrency):

    NAME = "Pesobit"
    SYMBOL = "PSB"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 62,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Pesobit Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb7


class PhoreMainnet(Cryptocurrency):

    NAME = "Phore"
    SYMBOL = "PHR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 444,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xd
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Phore Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xd4


class PinkcoinMainnet(Cryptocurrency):

    NAME = "Pinkcoin"
    SYMBOL = "PINK"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 117,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x3
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Pinkcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x83


class PivxMainnet(Cryptocurrency):

    NAME = "Pivx"
    SYMBOL = "PIVX"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 119,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xd
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xd4


class PivxTestnet(Cryptocurrency):

    NAME = "Pivx"
    SYMBOL = "PIVXTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x13
    PUBLIC_KEY_ADDRESS = 0x8b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x3a805837,
        "P2SH": 0x3a805837,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x3a8061a0,
        "P2SH": 0x3a8061a0,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class PoswCoinMainnet(Cryptocurrency):

    NAME = "Posw Coin"
    SYMBOL = "POSW"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 47,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Poswcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb7


class PotcoinMainnet(Cryptocurrency):

    NAME = "Potcoin"
    SYMBOL = "POT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 81,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Potcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb7


class ProjectCoinMainnet(Cryptocurrency):

    NAME = "Project Coin"
    SYMBOL = "PRJ"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 533,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18ProjectCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x75


class PutincoinMainnet(Cryptocurrency):

    NAME = "Putincoin"
    SYMBOL = "PUT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 122,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x14
    PUBLIC_KEY_ADDRESS = 0x37
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18PutinCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xb7


class QtumMainnet(Cryptocurrency):

    NAME = "Qtum"
    SYMBOL = "QTUM"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/qtumproject/qtum"
    COIN_TYPE = CoinType({
        "INDEX": 2301,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x32
    PUBLIC_KEY_ADDRESS = 0x3a
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "qc1",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class QtumTestnet(Cryptocurrency):

    NAME = "Qtum"
    SYMBOL = "QTUMTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/qtumproject/qtum"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x6e
    PUBLIC_KEY_ADDRESS = 0x78
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tq1",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x04358394,
        "P2SH": 0x04358394,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28,
        "P2WSH": 0x02575048,
        "P2WSH_IN_P2SH": 0x024285b5
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x043587cf,
        "P2SH": 0x043587cf,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262,
        "P2WSH": 0x02575483,
        "P2WSH_IN_P2SH": 0x024289ef
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class RSKMainnet(Cryptocurrency):

    NAME = "RSK"
    SYMBOL = "RBTC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 137,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x0
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18RSK Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class RSKTestnet(Cryptocurrency):

    NAME = "RSK"
    SYMBOL = "RBTCTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18RSK Testnet Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class RapidsMainnet(Cryptocurrency):

    NAME = "Rapids"
    SYMBOL = "RPD"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 320,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x6
    PUBLIC_KEY_ADDRESS = 0x3d
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "DarkNet Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x2e


class RavencoinMainnet(Cryptocurrency):

    NAME = "Ravencoin"
    SYMBOL = "RVN"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/RavenProject/Ravencoin"
    COIN_TYPE = CoinType({
        "INDEX": 175,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7a
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "ra",
        "VERSION": 0x0c
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = "Raven Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class RavencoinTestnet(Cryptocurrency):

    NAME = "Ravencoin"
    SYMBOL = "RVNTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/RavenProject/Ravencoin"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tr",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })


class ReddcoinMainnet(Cryptocurrency):

    NAME = "Reddcoin"
    SYMBOL = "RDD"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 4,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x3d
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Reddcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbd


class RippleMainnet(Cryptocurrency):

    NAME = "Ripple"
    SYMBOL = "XRP"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 144,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x00
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MASSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class RubycoinMainnet(Cryptocurrency):

    NAME = "Rubycoin"
    SYMBOL = "RBY"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 16,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x55
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Rubycoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbc


class SafecoinMainnet(Cryptocurrency):

    NAME = "Safecoin"
    SYMBOL = "SAFE"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 19165,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x56
    PUBLIC_KEY_ADDRESS = 0x3d
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Safecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbd


class SaluscoinMainnet(Cryptocurrency):

    NAME = "Saluscoin"
    SYMBOL = "SLS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 572,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Salus Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class ScribeMainnet(Cryptocurrency):

    NAME = "Scribe"
    SYMBOL = "SCRIBE"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 545,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x6e


class ShadowCashMainnet(Cryptocurrency):

    NAME = "Shadow Cash"
    SYMBOL = "SDC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/shadowproject/shadow"
    COIN_TYPE = CoinType({
        "INDEX": 35,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xee8031e8,
        "P2SH": 0xee8031e8,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xee80286a,
        "P2SH": 0xee80286a,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class ShadowCashTestnet(Cryptocurrency):

    NAME = "Shadow Cash"
    SYMBOL = "SDCTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/shadowproject/shadow"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x7f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x76c1077a,
        "P2SH": 0x76c1077a,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x76c0fdfb,
        "P2SH": 0x76c0fdfb,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xff


class SlimcoinMainnet(Cryptocurrency):

    NAME = "Slimcoin"
    SYMBOL = "SLM"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 63,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xef69ea80,
        "P2SH": 0xef69ea80,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xef6adf10,
        "P2SH": 0xef6adf10,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x46


class SlimcoinTestnet(Cryptocurrency):

    NAME = "Slimcoin"
    SYMBOL = "SLMTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x6f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x57


class SmileycoinMainnet(Cryptocurrency):

    NAME = "Smileycoin"
    SYMBOL = "SMLY"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 59,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x19
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x1e5631bc,
        "P2SH": 0x1e5631bc,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x1e562d9a,
        "P2SH": 0x1e562d9a,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Smileycoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x5


class SolarcoinMainnet(Cryptocurrency):

    NAME = "Solarcoin"
    SYMBOL = "SLR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 58,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x12
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18SolarCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x92


class StashMainnet(Cryptocurrency):

    NAME = "Stash"
    SYMBOL = "STASH"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 49344,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x10
    PUBLIC_KEY_ADDRESS = 0x4c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Stash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xcc


class StratisMainnet(Cryptocurrency):

    NAME = "Stratis"
    SYMBOL = "STRAT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 105,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Stratis Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class StratisTestnet(Cryptocurrency):

    NAME = "Stratis"
    SYMBOL = "STRATTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x41
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Stratis Test Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class SugarchainMainnet(Cryptocurrency):

    NAME = "Sugarchain"
    SYMBOL = "SUGAR"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 408,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "sugar",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Sugarchain Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class SugarchainTestnet(Cryptocurrency):

    NAME = "Sugarchain"
    SYMBOL = "SUGARTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x80
    PUBLIC_KEY_ADDRESS = 0x42
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "tugar",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x45f18bc,
        "P2SH": 0x45f18bc,
        "P2WPKH": 0x045f18bc,
        "P2WPKH_IN_P2SH": 0x044a4e28,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x45f1cf6,
        "P2SH": 0x45f1cf6,
        "P2WPKH": 0x045f1cf6,
        "P2WPKH_IN_P2SH": 0x044a5262,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Sugarchain Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class SyscoinMainnet(Cryptocurrency):

    NAME = "Syscoin"
    SYMBOL = "SYS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 57,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x3f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "sys",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Syscoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class TOACoinMainnet(Cryptocurrency):

    NAME = "TOA Coin"
    SYMBOL = "TOA"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 159,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x17
    PUBLIC_KEY_ADDRESS = 0x41
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18TOA Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc1


class ThoughtAIMainnet(Cryptocurrency):

    NAME = "Thought AI"
    SYMBOL = "THT"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 502,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x9
    PUBLIC_KEY_ADDRESS = 0x7
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x5aebd8c6,
        "P2SH": 0x5aebd8c6,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xfbc6a00d,
        "P2SH": 0xfbc6a00d,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x7b


class TronMainnet(Cryptocurrency):

    NAME = "Tron"
    SYMBOL = "TRX"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/tronprotocol/java-tron"

    COIN_TYPE = CoinType({
        "INDEX": 195,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x41

    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class TwinsMainnet(Cryptocurrency):

    NAME = "Twins"
    SYMBOL = "TWINS"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 970,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x53
    PUBLIC_KEY_ADDRESS = 0x49
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x42


class TwinsTestnet(Cryptocurrency):

    NAME = "Twins"
    SYMBOL = "TWINSTEST"
    NETWORK = "testnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x89
    PUBLIC_KEY_ADDRESS = 0x4c
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x3a805837,
        "P2SH": 0x3a805837,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x3a8061a0,
        "P2SH": 0x3a8061a0,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xed


class UltimateSecureCashMainnet(Cryptocurrency):

    NAME = "Ultimate Secure Cash"
    SYMBOL = "USC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 112,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x7d
    PUBLIC_KEY_ADDRESS = 0x44
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0xee8031e8,
        "P2SH": 0xee8031e8,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0xee80286a,
        "P2SH": 0xee80286a,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18UltimateSecureCash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xbf


class UnobtaniumMainnet(Cryptocurrency):

    NAME = "Unobtanium"
    SYMBOL = "UNO"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 92,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1e
    PUBLIC_KEY_ADDRESS = 0x82
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Unobtanium Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xe0


class VPNCoinMainnet(Cryptocurrency):

    NAME = "Virtual Cash"
    SYMBOL = "VASH"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 33,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x47
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18VpnCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc7


class VcashMainnet(Cryptocurrency):

    NAME = "Vcash"
    SYMBOL = "VC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 127,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x8
    PUBLIC_KEY_ADDRESS = 0x47
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Vcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc7


class VergeCurrencyMainnet(Cryptocurrency):

    NAME = "Verge Currency"
    SYMBOL = "XVG"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 77,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x21
    PUBLIC_KEY_ADDRESS = 0x1e
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18VERGE Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x9e


class VertcoinMainnet(Cryptocurrency):

    NAME = "Vertcoin"
    SYMBOL = "VTC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 28,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x5
    PUBLIC_KEY_ADDRESS = 0x47
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "vtc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x0488ade4,
        "P2WPKH_IN_P2SH": 0x0488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x0488b21e,
        "P2WPKH_IN_P2SH": 0x0488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Vertcoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ViacoinMainnet(Cryptocurrency):

    NAME = "Viacoin"
    SYMBOL = "VIA"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/viacoin/viacore-viacoin"
    COIN_TYPE = CoinType({
        "INDEX": 14,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x21
    PUBLIC_KEY_ADDRESS = 0x47
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "viacoin",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": 0x0488ade4,
        "P2WPKH_IN_P2SH": 0x0488ade4,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": 0x0488b21e,
        "P2WPKH_IN_P2SH": 0x0488b21e,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Viacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc7


class ViacoinTestnet(Cryptocurrency):

    NAME = "Viacoin"
    SYMBOL = "VIATEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/viacoin/viacore-viacoin"
    COIN_TYPE = CoinType({
        "INDEX": 14,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xc4
    PUBLIC_KEY_ADDRESS = 0x7f
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Viacoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xff


class VivoMainnet(Cryptocurrency):

    NAME = "Vivo"
    SYMBOL = "VIVO"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 166,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0xa
    PUBLIC_KEY_ADDRESS = 0x46
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18DarkCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc6


class WhitecoinMainnet(Cryptocurrency):

    NAME = "Whitecoin"
    SYMBOL = "XWC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 559,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x57
    PUBLIC_KEY_ADDRESS = 0x49
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x48894ed,
        "P2SH": 0x48894ed,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x4887f1e,
        "P2SH": 0x4887f1e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Whitecoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc9


class WincoinMainnet(Cryptocurrency):

    NAME = "Wincoin"
    SYMBOL = "WC"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 181,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c
    PUBLIC_KEY_ADDRESS = 0x49
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18WinCoin Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xc9


class XUEZMainnet(Cryptocurrency):

    NAME = "XUEZ"
    SYMBOL = "XUEZ"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 225,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x12
    PUBLIC_KEY_ADDRESS = 0x4b
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x221312b,
        "P2SH": 0x221312b,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x22d2533,
        "P2SH": 0x22d2533,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xd4


class XinFinMainnet(Cryptocurrency):

    NAME = "XinFin"
    SYMBOL = "XDC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/XinFinOrg/XDPoSChain"
    COIN_TYPE = CoinType({
        "INDEX": 550,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x05
    PUBLIC_KEY_ADDRESS = 0x00
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": "bc",
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x0488ade4,
        "P2SH": 0x0488ade4,
        "P2WPKH": 0x04b2430c,
        "P2WPKH_IN_P2SH": 0x049d7878,
        "P2WSH": 0x02aa7a99,
        "P2WSH_IN_P2SH": 0x0295b005
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x0488b21e,
        "P2SH": 0x0488b21e,
        "P2WPKH": 0x04b24746,
        "P2WPKH_IN_P2SH": 0x049d7cb2,
        "P2WSH": 0x02aa7ed3,
        "P2WSH_IN_P2SH": 0x0295b43f
    })

    MESSAGE_PREFIX = None
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80
    
class YcashMainnet(Cryptocurrency):

    NAME = "Ycash"
    SYMBOL = "YEC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/ycashfoundation/ycash"
    COIN_TYPE = CoinType({
        "INDEX": 347,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1c2c
    PUBLIC_KEY_ADDRESS = 0x1c28
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Ycash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ZClassicMainnet(Cryptocurrency):

    NAME = "ZClassic"
    SYMBOL = "ZCL"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 147,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x1cb8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Zcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ZcashMainnet(Cryptocurrency):

    NAME = "Zcash"
    SYMBOL = "ZEC"
    NETWORK = "mainnet"
    SOURCE_CODE = "https://github.com/zcash/zcash"
    COIN_TYPE = CoinType({
        "INDEX": 133,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cbd
    PUBLIC_KEY_ADDRESS = 0x1cb8
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Zcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


class ZcashTestnet(Cryptocurrency):

    NAME = "Zcash"
    SYMBOL = "ZECTEST"
    NETWORK = "testnet"
    SOURCE_CODE = "https://github.com/zcash/zcash"
    COIN_TYPE = CoinType({
        "INDEX": 1,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x1cba
    PUBLIC_KEY_ADDRESS = 0x1d25
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x4358394,
        "P2SH": 0x4358394,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x43587cf,
        "P2SH": 0x43587cf,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Zcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0xef


class ZencashMainnet(Cryptocurrency):

    NAME = "Zencash"
    SYMBOL = "ZEN"
    NETWORK = "mainnet"
    SOURCE_CODE = None
    COIN_TYPE = CoinType({
        "INDEX": 121,
        "HARDENED": True
    })

    SCRIPT_ADDRESS = 0x2096
    PUBLIC_KEY_ADDRESS = 0x2089
    SEGWIT_ADDRESS = SegwitAddress({
        "HRP": None,
        "VERSION": 0x00
    })

    EXTENDED_PRIVATE_KEY = ExtendedPrivateKey({
        "P2PKH": 0x488ade4,
        "P2SH": 0x488ade4,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })
    EXTENDED_PUBLIC_KEY = ExtendedPublicKey({
        "P2PKH": 0x488b21e,
        "P2SH": 0x488b21e,
        "P2WPKH": None,
        "P2WPKH_IN_P2SH": None,
        "P2WSH": None,
        "P2WSH_IN_P2SH": None
    })

    MESSAGE_PREFIX = "\x18Zcash Signed Message:\n"
    DEFAULT_PATH = f"m/44'/{str(COIN_TYPE)}/0'/0/0"
    WIF_SECRET_KEY = 0x80


def get_cryptocurrency(symbol: str) -> Any:

    for _, cryptocurrency in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(cryptocurrency):
            if issubclass(cryptocurrency, Cryptocurrency) and cryptocurrency != Cryptocurrency:
                if symbol == cryptocurrency.SYMBOL:
                    return cryptocurrency

    raise ValueError(f"Invalid Cryptocurrency '{symbol}' symbol.")
