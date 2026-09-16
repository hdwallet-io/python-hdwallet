#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import CustomDerivation
from hdwallet.hds import BIP32HD


def test_bip32_hd(data):
    bip32_hd: BIP32HD = BIP32HD(
        ecc=Cryptocurrency.ECC, wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX

    )

    bip32_hd.from_seed(
        seed=data["hds"]["BIP32"]["seed"]
    )

    assert isinstance(bip32_hd, BIP32HD)

    assert bip32_hd.name() == data["hds"]["BIP32"]["name"]
    assert bip32_hd.seed() == data["hds"]["BIP32"]["seed"]

    assert bip32_hd.root_xprivate_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP32"]["root-xprivate-key"]
    assert bip32_hd.root_xpublic_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP32"]["root-xpublic-key"]
    assert bip32_hd.root_private_key() == data["hds"]["BIP32"]["root-private-key"]
    assert bip32_hd.root_public_key() == data["hds"]["BIP32"]["root-public-key"]
    assert bip32_hd.root_chain_code() == data["hds"]["BIP32"]["root-chain-code"]

    bip32_hd.from_derivation(
        derivation= CustomDerivation(
            path=data["hds"]["BIP32"]["derivation"]["path"]
        )
    )
    assert bip32_hd.xprivate_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP32"]["derivation"]["xprivate-key"]
    assert bip32_hd.xpublic_key(
        version=Cryptocurrency.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH
    ) == data["hds"]["BIP32"]["derivation"]["xpublic-key"]
    assert bip32_hd.private_key() == data["hds"]["BIP32"]["derivation"]["private-key"]
    assert bip32_hd.wif() == data["hds"]["BIP32"]["derivation"]["wif"]
    assert bip32_hd.chain_code() == data["hds"]["BIP32"]["derivation"]["chain-code"]
    assert bip32_hd.public_key() == data["hds"]["BIP32"]["derivation"]["public-key"]
    assert bip32_hd.uncompressed() == data["hds"]["BIP32"]["derivation"]["uncompressed"]
    assert bip32_hd.compressed() == data["hds"]["BIP32"]["derivation"]["compressed"]
    assert bip32_hd.hash() == data["hds"]["BIP32"]["derivation"]["hash"]
    assert bip32_hd.depth() == data["hds"]["BIP32"]["derivation"]["depth"]
    assert bip32_hd.path() == data["hds"]["BIP32"]["derivation"]["path"]
    assert bip32_hd.index() == data["hds"]["BIP32"]["derivation"]["index"]
    assert bip32_hd.indexes() == data["hds"]["BIP32"]["derivation"]["indexes"]
    assert bip32_hd.fingerprint() == data["hds"]["BIP32"]["derivation"]["fingerprint"]
    assert bip32_hd.parent_fingerprint() == data["hds"]["BIP32"]["derivation"]["parent-fingerprint"]

    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2PKH,
        public_key_address_prefix=Cryptocurrency.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2pkh"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2SH,
        script_address_prefix=Cryptocurrency.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2sh"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2TR,
        hrp=Cryptocurrency.NETWORKS.MAINNET.HRP,
        witness_version=Cryptocurrency.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2tr"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2WPKH,
        hrp=Cryptocurrency.NETWORKS.MAINNET.HRP,
        witness_version=Cryptocurrency.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2wpkh"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2WPKH_IN_P2SH,
        script_address_prefix=Cryptocurrency.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2wpkh-in-p2sh"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2WSH,
        hrp=Cryptocurrency.NETWORKS.MAINNET.HRP,
        witness_version=Cryptocurrency.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WSH
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2wsh"]
    assert bip32_hd.address(
        address=Cryptocurrency.ADDRESSES.P2WSH_IN_P2SH,
        script_address_prefix=Cryptocurrency.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
    ) == data["hds"]["BIP32"]["derivation"]["addresses"]["p2wsh-in-p2sh"]
