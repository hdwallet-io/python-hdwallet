#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import BIP84Derivation
from hdwallet.hds import BIP84HD


def test_bip84_hd(data):
    bip84_hd: BIP84HD = BIP84HD(
        ecc=Cryptocurrency.ECC, wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX
    )

    bip84_hd.from_seed(
        seed=data["hds"]["BIP84"]["seed"]
    )

    assert isinstance(bip84_hd, BIP84HD)

    assert bip84_hd.name() == data["hds"]["BIP84"]["name"]
    assert bip84_hd.seed() == data["hds"]["BIP84"]["seed"]

    assert bip84_hd.root_xprivate_key() == data["hds"]["BIP84"]["root-xprivate-key"]
    assert bip84_hd.root_xpublic_key() == data["hds"]["BIP84"]["root-xpublic-key"]
    assert bip84_hd.root_private_key() == data["hds"]["BIP84"]["root-private-key"]
    assert bip84_hd.root_public_key() == data["hds"]["BIP84"]["root-public-key"]
    assert bip84_hd.root_chain_code() == data["hds"]["BIP84"]["root-chain-code"]

    derivation: BIP84Derivation = BIP84Derivation(
        coin_type=Cryptocurrency.COIN_TYPE
    )

    derivation.from_account(account=0)
    derivation.from_change(change="internal-chain")
    derivation.from_address(address=0)

    bip84_hd.from_derivation(
        derivation=derivation
    )

    assert bip84_hd.xprivate_key() == data["hds"]["BIP84"]["derivation"]["xprivate-key"]
    assert bip84_hd.xpublic_key() == data["hds"]["BIP84"]["derivation"]["xpublic-key"]
    assert bip84_hd.private_key() == data["hds"]["BIP84"]["derivation"]["private-key"]
    assert bip84_hd.wif() == data["hds"]["BIP84"]["derivation"]["wif"]
    assert bip84_hd.chain_code() == data["hds"]["BIP84"]["derivation"]["chain-code"]
    assert bip84_hd.public_key() == data["hds"]["BIP84"]["derivation"]["public-key"]
    assert bip84_hd.uncompressed() == data["hds"]["BIP84"]["derivation"]["uncompressed"]
    assert bip84_hd.compressed() == data["hds"]["BIP84"]["derivation"]["compressed"]
    assert bip84_hd.hash() == data["hds"]["BIP84"]["derivation"]["hash"]
    assert bip84_hd.depth() == data["hds"]["BIP84"]["derivation"]["depth"]
    assert bip84_hd.path() == data["hds"]["BIP84"]["derivation"]["path"]
    assert bip84_hd.index() == data["hds"]["BIP84"]["derivation"]["index"]
    assert bip84_hd.indexes() == data["hds"]["BIP84"]["derivation"]["indexes"]
    assert bip84_hd.fingerprint() == data["hds"]["BIP84"]["derivation"]["fingerprint"]
    assert bip84_hd.parent_fingerprint() == data["hds"]["BIP84"]["derivation"]["parent-fingerprint"]

    assert bip84_hd.address(
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    )   == data["hds"]["BIP84"]["derivation"]["address"]
