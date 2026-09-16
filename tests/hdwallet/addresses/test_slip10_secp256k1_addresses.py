#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.addresses.p2pkh import P2PKHAddress
from hdwallet.addresses.p2sh import P2SHAddress
from hdwallet.addresses.p2wpkh import P2WPKHAddress
from hdwallet.addresses.p2wpkh_in_p2sh import P2WPKHInP2SHAddress
from hdwallet.addresses.p2wsh import P2WSHAddress
from hdwallet.addresses.p2wsh_in_p2sh import P2WSHInP2SHAddress
from hdwallet.addresses.p2tr import P2TRAddress
from hdwallet.addresses.ethereum import EthereumAddress
from hdwallet.addresses.xinfin import XinFinAddress
from hdwallet.addresses.tron import TronAddress
from hdwallet.addresses.ripple import RippleAddress
from hdwallet.addresses.filecoin import FilecoinAddress
from hdwallet.addresses.cosmos import CosmosAddress
from hdwallet.addresses.avalanche import AvalancheAddress
from hdwallet.addresses.eos import EOSAddress
from hdwallet.addresses.ergo import ErgoAddress
from hdwallet.addresses.icon import IconAddress
from hdwallet.addresses.okt_chain import OKTChainAddress
from hdwallet.addresses.harmony import HarmonyAddress
from hdwallet.addresses.zilliqa import ZilliqaAddress
from hdwallet.addresses.injective import InjectiveAddress


def test_p2pkh_address(data):

    assert P2PKHAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["name"]

    assert P2PKHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["encode"]

    assert P2PKHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["encode"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["compressed"]["decode"]


    assert P2PKHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["encode"]

    assert P2PKHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["encode"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2PKH"]["uncompressed"]["decode"]


def test_p2sh_address(data):

    assert P2SHAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["name"]

    assert P2SHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["encode"]

    assert P2SHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["encode"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["compressed"]["decode"]


    assert P2SHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["encode"]

    assert P2SHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["encode"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2SH"]["uncompressed"]["decode"]


def test_p2wpkh_address(data):

    assert P2WPKHAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["name"]

    assert P2WPKHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["encode"]

    assert P2WPKHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["encode"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["compressed"]["decode"]


    assert P2WPKHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["encode"]

    assert P2WPKHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["encode"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH"]["uncompressed"]["decode"]


def test_p2pkh_in_p2sh_address(data):

    assert P2WPKHInP2SHAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["name"]

    assert P2WPKHInP2SHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["encode"]

    assert P2WPKHInP2SHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["encode"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["compressed"]["decode"]


    assert P2WPKHInP2SHAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["encode"]

    assert P2WPKHInP2SHAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["encode"],
        script_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["args"]["script_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2WPKH-In-P2SH"]["uncompressed"]["decode"]


def test_p2tr_address(data):

    assert P2TRAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["name"]

    assert P2TRAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["compressed"]["encode"]

    assert P2TRAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["compressed"]["decode"]


    assert P2TRAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["uncompressed"]["encode"]

    assert P2TRAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["P2TR"]["uncompressed"]["decode"]


def test_ethereum_address(data):

    assert EthereumAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["name"]

    assert EthereumAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["encode"]

    assert EthereumAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["compressed"]["decode"]

    assert EthereumAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["encode"]

    assert EthereumAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ethereum"]["uncompressed"]["decode"]


def test_xinfin_address(data):

    assert XinFinAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["name"]

    assert XinFinAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["encode"]

    assert XinFinAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["compressed"]["decode"]

    assert XinFinAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["encode"]

    assert XinFinAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["XinFin"]["uncompressed"]["decode"]


def test_tron_address(data):

    assert TronAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["name"]

    assert TronAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["encode"]

    assert TronAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["compressed"]["decode"]

    assert TronAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["encode"]

    assert TronAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["encode"],
        skip_checksum_encode=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["args"]["skip_checksum_encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Tron"]["uncompressed"]["decode"]


def test_ripple_address(data):

    assert RippleAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["name"]

    assert RippleAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["encode"]

    assert RippleAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["encode"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["compressed"]["decode"]


    assert RippleAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["encode"]

    assert RippleAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["encode"],
        public_key_address_prefix=int(data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["args"]["public_key_address_prefix"], base=16),
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ripple"]["uncompressed"]["decode"]


def test_filecoin_address(data):

    assert FilecoinAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["name"]

    assert FilecoinAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["encode"]

    assert FilecoinAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["compressed"]["decode"]


    assert FilecoinAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["encode"]

    assert FilecoinAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Filecoin"]["uncompressed"]["decode"]


def test_cosmos_address(data):

    assert CosmosAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["name"]

    assert CosmosAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["args"]["hrp"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["encode"]

    assert CosmosAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["encode"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["compressed"]["decode"]


    assert CosmosAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["encode"]

    assert CosmosAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["encode"],
        hrp=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["args"]["hrp"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Cosmos"]["uncompressed"]["decode"]


def test_avalanche_address(data):

    assert AvalancheAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["name"]

    assert AvalancheAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["encode"]

    assert AvalancheAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["compressed"]["decode"]


    assert AvalancheAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["encode"]

    assert AvalancheAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["args"]["address_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Avalanche"]["uncompressed"]["decode"]


def test_eos_address(data):

    assert EOSAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["name"]

    assert EOSAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["compressed"]["encode"]

    assert EOSAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["compressed"]["decode"]


    assert EOSAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["uncompressed"]["encode"]

    assert EOSAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["EOS"]["uncompressed"]["decode"]

def test_ergo_address(data):

    assert ErgoAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["name"]

    assert ErgoAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["address_type"],
        network_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["network_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["encode"]

    assert ErgoAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["address_type"],
        network_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["network_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["compressed"]["decode"]


    assert ErgoAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["address_type"],
        network_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["network_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["encode"]

    assert ErgoAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["encode"],
        address_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["address_type"],
        network_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["network_type"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Ergo"]["uncompressed"]["decode"]


def test_okt_chain_address(data):

    assert OKTChainAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["name"]

    assert OKTChainAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["compressed"]["encode"]

    assert OKTChainAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["compressed"]["decode"]


    assert OKTChainAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["uncompressed"]["encode"]

    assert OKTChainAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["OKT-Chain"]["uncompressed"]["decode"]


def test_harmony_address(data):

    assert HarmonyAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["name"]

    assert HarmonyAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["compressed"]["encode"]

    assert HarmonyAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["compressed"]["decode"]


    assert HarmonyAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["uncompressed"]["encode"]

    assert HarmonyAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Harmony"]["uncompressed"]["decode"]


def test_zilliqa_address(data):

    assert ZilliqaAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["name"]

    assert ZilliqaAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["compressed"]["encode"]

    assert ZilliqaAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["compressed"]["decode"]


    assert ZilliqaAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["uncompressed"]["encode"]

    assert ZilliqaAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Zilliqa"]["uncompressed"]["decode"]


def test_injective_address(data):

    assert InjectiveAddress.name() == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["name"]

    assert InjectiveAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["compressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["compressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["compressed"]["encode"]

    assert InjectiveAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["compressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["compressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["compressed"]["decode"]


    assert InjectiveAddress.encode(
        public_key= data["addresses"]["SLIP10-Secp256k1"]["uncompressed-public-key"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["uncompressed"]["args"]["public_key_type"]
    ) == data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["uncompressed"]["encode"]

    assert InjectiveAddress.decode(
        address=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["uncompressed"]["encode"],
        public_key_type=data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["uncompressed"]["args"]["public_key_type"]
    ) ==  data["addresses"]["SLIP10-Secp256k1"]["addresses"]["Injective"]["uncompressed"]["decode"]
