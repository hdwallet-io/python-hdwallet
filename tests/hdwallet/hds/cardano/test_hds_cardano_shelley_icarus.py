#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Cardano
from hdwallet.hds import CardanoHD
from hdwallet.derivations import CustomDerivation
from hdwallet.derivations import (
    CIP1852Derivation, ROLES
)


def test_cardano_shelley_icarus_without_passphrase_hd(data):

    cardano_hd: CardanoHD = CardanoHD(
        cardano_type=Cardano.TYPES.SHELLEY_ICARUS
    )

    cardano_hd.from_seed(
        seed=data["hds"]["Cardano"]["shelley-icarus"]["seed"]
    )

    assert isinstance(cardano_hd, CardanoHD)

    assert cardano_hd.name() == data["hds"]["Cardano"]["shelley-icarus"]["name"]
    assert cardano_hd.seed() == data["hds"]["Cardano"]["shelley-icarus"]["seed"]

    assert cardano_hd.root_xprivate_key() == data["hds"]["Cardano"]["shelley-icarus"]["root-xprivate-key"]
    assert cardano_hd.root_xpublic_key( ) == data["hds"]["Cardano"]["shelley-icarus"]["root-xpublic-key"]
    assert cardano_hd.root_private_key() == data["hds"]["Cardano"]["shelley-icarus"]["root-private-key"]
    assert cardano_hd.root_public_key() == data["hds"]["Cardano"]["shelley-icarus"]["root-public-key"]
    assert cardano_hd.root_chain_code() == data["hds"]["Cardano"]["shelley-icarus"]["root-chain-code"]

    cip1852_derivation: CIP1852Derivation = CIP1852Derivation(
        coin_type=Cardano.COIN_TYPE, role=ROLES.STAKING_KEY 
    )
    cip1852_derivation.from_account(account=0)
    cip1852_derivation.from_address(address=0)

    cardano_hd.from_derivation(
        derivation=cip1852_derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["parent-fingerprint"]
    assert cardano_hd.address(address_type="staking") == data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["address"]

    cip1852_derivation.from_role(
        role=ROLES.EXTERNAL_CHAIN
    )

    cardano_hd.update_derivation(
        derivation=cip1852_derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["parent-fingerprint"]
    assert cardano_hd.address(
        address_type="payment", staking_public_key=data["hds"]["Cardano"]["shelley-icarus"]["derivation-staking"]["public-key"]
    ) == data["hds"]["Cardano"]["shelley-icarus"]["derivation-payment"]["address"]


def test_cardano_shelley_icarus_with_passphrase_hd(data):

    cardano_hd: CardanoHD = CardanoHD(
        cardano_type=Cardano.TYPES.SHELLEY_ICARUS
    )

    cardano_hd.from_seed(
        seed=data["hds"]["Cardano"]["shelley-icarus-passphrase"]["seed"],
        passphrase=data["hds"]["Cardano"]["shelley-icarus-passphrase"]["passphrase"],
    )

    assert isinstance(cardano_hd, CardanoHD)

    assert cardano_hd.name() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["name"]
    assert cardano_hd.seed() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["seed"]

    assert cardano_hd.root_xprivate_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["root-xprivate-key"]
    assert cardano_hd.root_xpublic_key( ) == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["root-xpublic-key"]
    assert cardano_hd.root_private_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["root-private-key"]
    assert cardano_hd.root_public_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["root-public-key"]
    assert cardano_hd.root_chain_code() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["root-chain-code"]

    cip1852_derivation: CIP1852Derivation = CIP1852Derivation(
        coin_type=Cardano.COIN_TYPE, role=ROLES.STAKING_KEY 
    )
    cip1852_derivation.from_account(account=0)
    cip1852_derivation.from_address(address=0)

    cardano_hd.from_derivation(
        derivation=cip1852_derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["parent-fingerprint"]
    assert cardano_hd.address(address_type="staking") == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["address"]

    cip1852_derivation.from_role(
        role=ROLES.EXTERNAL_CHAIN
    )

    cardano_hd.update_derivation(
        derivation=cip1852_derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["parent-fingerprint"]
    assert cardano_hd.address(
        address_type="payment", staking_public_key=data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-staking"]["public-key"]
    ) == data["hds"]["Cardano"]["shelley-icarus-passphrase"]["derivation-payment"]["address"]
