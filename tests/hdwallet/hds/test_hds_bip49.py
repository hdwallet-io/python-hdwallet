#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import BIP49Derivation
from hdwallet.hds import BIP49HD


def test_bip49_hd(data):
    bip49_hd: BIP49HD = BIP49HD(
        ecc=Cryptocurrency.ECC, wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX
    )

    bip49_hd.from_seed(
        seed=data["hds"]["BIP49"]["seed"]
    )

    assert isinstance(bip49_hd, BIP49HD)

    assert bip49_hd.name() == data["hds"]["BIP49"]["name"]
    assert bip49_hd.seed() == data["hds"]["BIP49"]["seed"]

    assert bip49_hd.root_xprivate_key() == data["hds"]["BIP49"]["root-xprivate-key"]
    assert bip49_hd.root_xpublic_key() == data["hds"]["BIP49"]["root-xpublic-key"]
    assert bip49_hd.root_private_key() == data["hds"]["BIP49"]["root-private-key"]
    assert bip49_hd.root_public_key() == data["hds"]["BIP49"]["root-public-key"]
    assert bip49_hd.root_chain_code() == data["hds"]["BIP49"]["root-chain-code"]

    derivation: BIP49Derivation = BIP49Derivation(
        coin_type=Cryptocurrency.COIN_TYPE
    )

    derivation.from_account(account=0)
    derivation.from_change(change="internal-chain")
    derivation.from_address(address=0)

    bip49_hd.from_derivation(
        derivation=derivation
    )

    assert bip49_hd.xprivate_key() == data["hds"]["BIP49"]["derivation"]["xprivate-key"]
    assert bip49_hd.xpublic_key() == data["hds"]["BIP49"]["derivation"]["xpublic-key"]
    assert bip49_hd.private_key() == data["hds"]["BIP49"]["derivation"]["private-key"]
    assert bip49_hd.wif() == data["hds"]["BIP49"]["derivation"]["wif"]
    assert bip49_hd.chain_code() == data["hds"]["BIP49"]["derivation"]["chain-code"]
    assert bip49_hd.public_key() == data["hds"]["BIP49"]["derivation"]["public-key"]
    assert bip49_hd.uncompressed() == data["hds"]["BIP49"]["derivation"]["uncompressed"]
    assert bip49_hd.compressed() == data["hds"]["BIP49"]["derivation"]["compressed"]
    assert bip49_hd.hash() == data["hds"]["BIP49"]["derivation"]["hash"]
    assert bip49_hd.depth() == data["hds"]["BIP49"]["derivation"]["depth"]
    assert bip49_hd.path() == data["hds"]["BIP49"]["derivation"]["path"]
    assert bip49_hd.index() == data["hds"]["BIP49"]["derivation"]["index"]
    assert bip49_hd.indexes() == data["hds"]["BIP49"]["derivation"]["indexes"]
    assert bip49_hd.fingerprint() == data["hds"]["BIP49"]["derivation"]["fingerprint"]
    assert bip49_hd.parent_fingerprint() == data["hds"]["BIP49"]["derivation"]["parent-fingerprint"]

    assert bip49_hd.address(
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    )   == data["hds"]["BIP49"]["derivation"]["address"]
