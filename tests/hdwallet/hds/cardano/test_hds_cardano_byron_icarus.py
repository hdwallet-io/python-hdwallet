#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Cardano
from hdwallet.hds import CardanoHD
from hdwallet.derivations import BIP44Derivation


def test_cardano_byron_icarus_without_passphrase_hd(data):

    cardano_hd: CardanoHD = CardanoHD(
        cardano_type=Cardano.TYPES.BYRON_ICARUS
    )

    cardano_hd.from_seed(
        seed=data["hds"]["Cardano"]["byron-icarus"]["seed"]
    )

    assert isinstance(cardano_hd, CardanoHD)

    assert cardano_hd.name() == data["hds"]["Cardano"]["byron-icarus"]["name"]
    assert cardano_hd.seed() == data["hds"]["Cardano"]["byron-icarus"]["seed"]

    assert cardano_hd.root_xprivate_key() == data["hds"]["Cardano"]["byron-icarus"]["root-xprivate-key"]
    assert cardano_hd.root_xpublic_key( ) == data["hds"]["Cardano"]["byron-icarus"]["root-xpublic-key"]
    assert cardano_hd.root_private_key() == data["hds"]["Cardano"]["byron-icarus"]["root-private-key"]
    assert cardano_hd.root_public_key() == data["hds"]["Cardano"]["byron-icarus"]["root-public-key"]
    assert cardano_hd.root_chain_code() == data["hds"]["Cardano"]["byron-icarus"]["root-chain-code"]

    derivation: BIP44Derivation = BIP44Derivation(
        coin_type=Cardano.COIN_TYPE
    )
    derivation.from_account(account=0)
    derivation.from_change(change="external-chain")
    derivation.from_address(address=0)

    cardano_hd.from_derivation(
        derivation=derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["parent-fingerprint"]
    assert cardano_hd.address() == data["hds"]["Cardano"]["byron-icarus"]["derivation"]["address"]


def test_cardano_byron_icarus_with_passphrase_hd(data):

    cardano_hd: CardanoHD = CardanoHD(
        cardano_type=Cardano.TYPES.BYRON_ICARUS
    )

    cardano_hd.from_seed(
        seed=data["hds"]["Cardano"]["byron-icarus-passphrase"]["seed"],
        passphrase=data["hds"]["Cardano"]["byron-icarus-passphrase"]["passphrase"]
    )

    assert isinstance(cardano_hd, CardanoHD)

    assert cardano_hd.name() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["name"]
    assert cardano_hd.seed() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["seed"]

    assert cardano_hd.root_xprivate_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["root-xprivate-key"]
    assert cardano_hd.root_xpublic_key( ) == data["hds"]["Cardano"]["byron-icarus-passphrase"]["root-xpublic-key"]
    assert cardano_hd.root_private_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["root-private-key"]
    assert cardano_hd.root_public_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["root-public-key"]
    assert cardano_hd.root_chain_code() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["root-chain-code"]

    derivation: BIP44Derivation = BIP44Derivation(
        coin_type=Cardano.COIN_TYPE
    )
    derivation.from_account(account=0)
    derivation.from_change(change="external-chain")
    derivation.from_address(address=0)

    cardano_hd.from_derivation(
        derivation=derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["parent-fingerprint"]
    assert cardano_hd.address() == data["hds"]["Cardano"]["byron-icarus-passphrase"]["derivation"]["address"]
