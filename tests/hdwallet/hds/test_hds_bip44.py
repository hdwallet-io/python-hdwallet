#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import BIP44Derivation
from hdwallet.hds import BIP44HD


def test_bip44_hd(data):
    bip44_hd: BIP44HD = BIP44HD(
        ecc=Cryptocurrency.ECC, wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX
    )

    bip44_hd.from_seed(
        seed=data["hds"]["BIP44"]["seed"]
    )

    assert isinstance(bip44_hd, BIP44HD)

    assert bip44_hd.name() == data["hds"]["BIP44"]["name"]
    assert bip44_hd.seed() == data["hds"]["BIP44"]["seed"]

    assert bip44_hd.root_xprivate_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP44"]["root-xprivate-key"]
    assert bip44_hd.root_xpublic_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP44"]["root-xpublic-key"]
    assert bip44_hd.root_private_key() == data["hds"]["BIP44"]["root-private-key"]
    assert bip44_hd.root_public_key() == data["hds"]["BIP44"]["root-public-key"]
    assert bip44_hd.root_chain_code() == data["hds"]["BIP44"]["root-chain-code"]

    derivation: BIP44Derivation = BIP44Derivation(
        coin_type=Cryptocurrency.COIN_TYPE
    )

    derivation.from_account(account=0)
    derivation.from_change(change="internal-chain")
    derivation.from_address(address=0)

    bip44_hd.from_derivation(
        derivation=derivation
    )

    assert bip44_hd.xprivate_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP44"]["derivation"]["xprivate-key"]
    assert bip44_hd.xpublic_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP44"]["derivation"]["xpublic-key"]
    assert bip44_hd.private_key() == data["hds"]["BIP44"]["derivation"]["private-key"]
    assert bip44_hd.wif() == data["hds"]["BIP44"]["derivation"]["wif"]
    assert bip44_hd.chain_code() == data["hds"]["BIP44"]["derivation"]["chain-code"]
    assert bip44_hd.public_key() == data["hds"]["BIP44"]["derivation"]["public-key"]
    assert bip44_hd.uncompressed() == data["hds"]["BIP44"]["derivation"]["uncompressed"]
    assert bip44_hd.compressed() == data["hds"]["BIP44"]["derivation"]["compressed"]
    assert bip44_hd.hash() == data["hds"]["BIP44"]["derivation"]["hash"]
    assert bip44_hd.depth() == data["hds"]["BIP44"]["derivation"]["depth"]
    assert bip44_hd.path() == data["hds"]["BIP44"]["derivation"]["path"]
    assert bip44_hd.index() == data["hds"]["BIP44"]["derivation"]["index"]
    assert bip44_hd.indexes() == data["hds"]["BIP44"]["derivation"]["indexes"]
    assert bip44_hd.fingerprint() == data["hds"]["BIP44"]["derivation"]["fingerprint"]
    assert bip44_hd.parent_fingerprint() == data["hds"]["BIP44"]["derivation"]["parent-fingerprint"]

    assert bip44_hd.address(
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    )   == data["hds"]["BIP44"]["derivation"]["address"]
