#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.hds import HDS


def test_monero_from_private_key(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Monero"]["from-private-key"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Monero"]["from-private-key"]["hd"]
        ),
        network=data["hdwallet"]["Monero"]["from-private-key"]["network"]
    ).from_private_key(
        private_key=data["hdwallet"]["Monero"]["from-private-key"]["private_key"]
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Monero"]["derivation"]["name"])(
            **data["hdwallet"]["Monero"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Monero"]["from-private-key"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Monero"]["from-private-key"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Monero"]["from-private-key"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Monero"]["from-private-key"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Monero"]["from-private-key"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Monero"]["from-private-key"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Monero"]["from-private-key"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Monero"]["from-private-key"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Monero"]["from-private-key"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Monero"]["from-private-key"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Monero"]["from-private-key"]["hd"]
    assert hdwallet.spend_private_key() == data["hdwallet"]["Monero"]["from-private-key"]["spend_private_key"]
    assert hdwallet.view_private_key() == data["hdwallet"]["Monero"]["from-private-key"]["view_private_key"]
    assert hdwallet.spend_public_key() == data["hdwallet"]["Monero"]["from-private-key"]["spend_public_key"]
    assert hdwallet.view_public_key() == data["hdwallet"]["Monero"]["from-private-key"]["view_public_key"]
    assert hdwallet.primary_address() == data["hdwallet"]["Monero"]["from-private-key"]["primary_address"]
    assert hdwallet.sub_address() == data["hdwallet"]["Monero"]["from-private-key"]["derivations"][-1]["sub_address"]

    assert hdwallet.dumps() == data["hdwallet"]["Monero"]["from-private-key"]

    dump = data["hdwallet"]["Monero"]["from-private-key"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Monero"]["from-private-key"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
