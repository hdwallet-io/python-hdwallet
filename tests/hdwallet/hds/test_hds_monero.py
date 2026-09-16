#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.cryptocurrencies import Monero
from hdwallet.hds.monero import MoneroHD


def test_monero_hd(data):

    monero_hd = MoneroHD(
        network=Monero.NETWORKS.MAINNET
    )

    monero_hd.from_seed(
        seed=data["hds"]["Monero"]["seed"]
    )

    assert isinstance(monero_hd, MoneroHD)

    assert monero_hd.name() == data["hds"]["Monero"]["name"]
    assert monero_hd.seed() == data["hds"]["Monero"]["seed"]

    assert monero_hd.spend_private_key() == data["hds"]["Monero"]["spend-private-key"]
    assert monero_hd.view_private_key() == data["hds"]["Monero"]["view-private-key"]
    assert monero_hd.spend_public_key() == data["hds"]["Monero"]["spend-public-key"]
    assert monero_hd.view_public_key() == data["hds"]["Monero"]["view-public-key"]
    assert monero_hd.primary_address() == data["hds"]["Monero"]["primary-address"]
    assert monero_hd.integrated_address(
        payment_id=data["hds"]["Monero"]["payment-id"]
    ) == data["hds"]["Monero"]["integrated-address"]

    for address in data["hds"]["Monero"]["sub-addresses"]:
        assert monero_hd.sub_address(
            minor=address["minor"], major=address["major"]
        ) == address["address"]
