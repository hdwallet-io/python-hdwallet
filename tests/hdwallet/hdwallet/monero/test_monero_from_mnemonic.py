#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.mnemonics import MoneroMnemonic
from hdwallet.hds import HDS


def test_monero_from_mnemonic(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Monero"]["dumps"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Monero"]["dumps"]["hd"]
        ),
        network=data["hdwallet"]["Monero"]["dumps"]["network"],
        language=data["hdwallet"]["Monero"]["dumps"]["language"].lower(),
        payment_id="ad17dc6e6793d178"
    ).from_mnemonic(
        mnemonic=MoneroMnemonic(
            mnemonic=data["hdwallet"]["Monero"]["dumps"]["mnemonic"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Monero"]["derivation"]["name"])(
            **data["hdwallet"]["Monero"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Monero"]["dumps"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Monero"]["dumps"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Monero"]["dumps"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Monero"]["dumps"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Monero"]["dumps"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Monero"]["dumps"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Monero"]["dumps"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Monero"]["dumps"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Monero"]["dumps"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Monero"]["dumps"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Monero"]["dumps"]["hd"]
    assert hdwallet.spend_private_key() == data["hdwallet"]["Monero"]["dumps"]["spend_private_key"]
    assert hdwallet.view_private_key() == data["hdwallet"]["Monero"]["dumps"]["view_private_key"]
    assert hdwallet.spend_public_key() == data["hdwallet"]["Monero"]["dumps"]["spend_public_key"]
    assert hdwallet.view_public_key() == data["hdwallet"]["Monero"]["dumps"]["view_public_key"]
    assert hdwallet.primary_address() == data["hdwallet"]["Monero"]["dumps"]["primary_address"]
    assert hdwallet.integrated_address(
        payment_id="ad17dc6e6793d178"
    ) == data["hdwallet"]["Monero"]["dumps"]["integrated_address"]

    assert hdwallet.sub_address() == data["hdwallet"]["Monero"]["dumps"]["derivations"][-1]["sub_address"]

    assert hdwallet.dumps() == data["hdwallet"]["Monero"]["dumps"]

    dump = data["hdwallet"]["Monero"]["dumps"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Monero"]["dumps"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
