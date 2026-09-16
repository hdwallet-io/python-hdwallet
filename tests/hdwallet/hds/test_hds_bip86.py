#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import BIP86Derivation
from hdwallet.hds import BIP86HD

def test_bip86_hd(data):
    bip86_hd: BIP86HD = BIP86HD(
        ecc=Cryptocurrency.ECC,
        coin_type=Cryptocurrency.COIN_TYPE,
        wif_prefix=Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX,
        account=0,
        change="external-chain",
        address=0
    )

    bip86_hd.from_seed(
        seed=data["hds"]["BIP86"]["seed"]
    )

    assert isinstance(bip86_hd, BIP86HD)

    assert bip86_hd.name() == data["hds"]["BIP86"]["name"]
    assert bip86_hd.seed() == data["hds"]["BIP86"]["seed"]

    assert bip86_hd.root_xprivate_key() == data["hds"]["BIP86"]["root-xprivate-key"]
    assert bip86_hd.root_xpublic_key() == data["hds"]["BIP86"]["root-xpublic-key"]
    assert bip86_hd.root_private_key() == data["hds"]["BIP86"]["root-private-key"]
    assert bip86_hd.root_public_key() == data["hds"]["BIP86"]["root-public-key"]
    assert bip86_hd.root_chain_code() == data["hds"]["BIP86"]["root-chain-code"]

    derivation: BIP86Derivation = BIP86Derivation(
        coin_type=Cryptocurrency.COIN_TYPE
    )

    derivation.from_account(account=0)
    derivation.from_change(change="external-chain")
    derivation.from_address(address=1)
    bip86_hd.from_derivation(
        derivation=derivation
    )

    assert bip86_hd.xprivate_key() == data["hds"]["BIP86"]["derivation"]["xprivate-key"]
    assert bip86_hd.xpublic_key() == data["hds"]["BIP86"]["derivation"]["xpublic-key"]
    assert bip86_hd.private_key() == data["hds"]["BIP86"]["derivation"]["private-key"]
    assert bip86_hd.wif() == data["hds"]["BIP86"]["derivation"]["wif"]
    assert bip86_hd.chain_code() == data["hds"]["BIP86"]["derivation"]["chain-code"]
    assert bip86_hd.public_key() == data["hds"]["BIP86"]["derivation"]["public-key"]
    assert bip86_hd.uncompressed() == data["hds"]["BIP86"]["derivation"]["uncompressed"]
    assert bip86_hd.compressed() == data["hds"]["BIP86"]["derivation"]["compressed"]
    assert bip86_hd.hash() == data["hds"]["BIP86"]["derivation"]["hash"]
    assert bip86_hd.depth() == data["hds"]["BIP86"]["derivation"]["depth"]
    assert bip86_hd.path() == data["hds"]["BIP86"]["derivation"]["path"]
    assert bip86_hd.index() == data["hds"]["BIP86"]["derivation"]["index"]
    assert bip86_hd.indexes() == data["hds"]["BIP86"]["derivation"]["indexes"]
    assert bip86_hd.fingerprint() == data["hds"]["BIP86"]["derivation"]["fingerprint"]
    assert bip86_hd.parent_fingerprint() == data["hds"]["BIP86"]["derivation"]["parent-fingerprint"]

    assert bip86_hd.address(
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    )   == data["hds"]["BIP86"]["derivation"]["address"]
