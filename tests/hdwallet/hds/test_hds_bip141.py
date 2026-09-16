#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import CustomDerivation
from hdwallet.hds import BIP141HD


def test_bip141_hd(data):
    bip141_hd: BIP141HD = BIP141HD(
        ecc=Cryptocurrency.ECC, wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX, semantic="p2wpkh"
    )

    bip141_hd.from_seed(
        seed=data["hds"]["BIP141"]["seed"]
    )

    assert isinstance(bip141_hd, BIP141HD)

    assert bip141_hd.name() == data["hds"]["BIP141"]["name"]
    assert bip141_hd.seed() == data["hds"]["BIP141"]["seed"]
    assert bip141_hd.semantic() == "p2wpkh"

    assert bip141_hd.root_xprivate_key() == data["hds"]["BIP141"]["root-xprivate-key"]
    assert bip141_hd.root_xpublic_key() == data["hds"]["BIP141"]["root-xpublic-key"]
    assert bip141_hd.root_private_key() == data["hds"]["BIP141"]["root-private-key"]
    assert bip141_hd.root_public_key() == data["hds"]["BIP141"]["root-public-key"]
    assert bip141_hd.root_chain_code() == data["hds"]["BIP141"]["root-chain-code"]

    bip141_hd.from_derivation(
        derivation= CustomDerivation(
            path=data["hds"]["BIP141"]["derivation"]["path"]
        )
    )
    assert bip141_hd.xprivate_key() == data["hds"]["BIP141"]["derivation"]["xprivate-key"]
    assert bip141_hd.xpublic_key() == data["hds"]["BIP141"]["derivation"]["xpublic-key"]
    assert bip141_hd.private_key() == data["hds"]["BIP141"]["derivation"]["private-key"]
    assert bip141_hd.wif() == data["hds"]["BIP141"]["derivation"]["wif"]
    assert bip141_hd.chain_code() == data["hds"]["BIP141"]["derivation"]["chain-code"]
    assert bip141_hd.public_key() == data["hds"]["BIP141"]["derivation"]["public-key"]
    assert bip141_hd.uncompressed() == data["hds"]["BIP141"]["derivation"]["uncompressed"]
    assert bip141_hd.compressed() == data["hds"]["BIP141"]["derivation"]["compressed"]
    assert bip141_hd.hash() == data["hds"]["BIP141"]["derivation"]["hash"]
    assert bip141_hd.depth() == data["hds"]["BIP141"]["derivation"]["depth"]
    assert bip141_hd.path() == data["hds"]["BIP141"]["derivation"]["path"]
    assert bip141_hd.index() == data["hds"]["BIP141"]["derivation"]["index"]
    assert bip141_hd.indexes() == data["hds"]["BIP141"]["derivation"]["indexes"]
    assert bip141_hd.fingerprint() == data["hds"]["BIP141"]["derivation"]["fingerprint"]
    assert bip141_hd.parent_fingerprint() == data["hds"]["BIP141"]["derivation"]["parent-fingerprint"]

    assert bip141_hd.address(
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    )   == data["hds"]["BIP141"]["derivation"]["address"]
