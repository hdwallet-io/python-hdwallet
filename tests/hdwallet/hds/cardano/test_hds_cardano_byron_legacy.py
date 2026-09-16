#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Cardano
from hdwallet.hds import CardanoHD
from hdwallet.derivations import CustomDerivation


def test_cardano_byron_legacy_hd(data):
    cardano_hd: CardanoHD = CardanoHD(
        cardano_type=Cardano.TYPES.BYRON_LEGACY
    )

    cardano_hd.from_seed(
        seed=data["hds"]["Cardano"]["byron-legacy"]["seed"]
    )

    assert isinstance(cardano_hd, CardanoHD)

    assert cardano_hd.name() == data["hds"]["Cardano"]["byron-legacy"]["name"]
    assert cardano_hd.seed() == data["hds"]["Cardano"]["byron-legacy"]["seed"]

    assert cardano_hd.root_xprivate_key() == data["hds"]["Cardano"]["byron-legacy"]["root-xprivate-key"]
    assert cardano_hd.root_xpublic_key( ) == data["hds"]["Cardano"]["byron-legacy"]["root-xpublic-key"]
    assert cardano_hd.root_private_key() == data["hds"]["Cardano"]["byron-legacy"]["root-private-key"]
    assert cardano_hd.root_public_key() == data["hds"]["Cardano"]["byron-legacy"]["root-public-key"]
    assert cardano_hd.root_chain_code() == data["hds"]["Cardano"]["byron-legacy"]["root-chain-code"]

    derivation: CustomDerivation = CustomDerivation(
        path=data["hds"]["Cardano"]["byron-legacy"]["derivation"]["path"]
    )

    cardano_hd.from_derivation(
        derivation=derivation
    )

    assert cardano_hd.xprivate_key() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["xprivate-key"]
    assert cardano_hd.xpublic_key() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["xpublic-key"]
    assert cardano_hd.private_key() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["private-key"]
    assert cardano_hd.chain_code() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["chain-code"]
    assert cardano_hd.public_key() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["public-key"]
    assert cardano_hd.depth() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["depth"]
    assert cardano_hd.path() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["path"]
    assert cardano_hd.index() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["index"]
    assert cardano_hd.indexes() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["indexes"]
    assert cardano_hd.fingerprint() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["fingerprint"]
    assert cardano_hd.parent_fingerprint() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["parent-fingerprint"]
    assert cardano_hd.address() == data["hds"]["Cardano"]["byron-legacy"]["derivation"]["address"]
