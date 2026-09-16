#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.hds import HDS


def test_monero_from_seed(data):

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
    ).from_spend_private_key(
        spend_private_key=data["hdwallet"]["Monero"]["dumps"]["spend_private_key"]
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Monero"]["derivation"]["name"])(
            **data["hdwallet"]["Monero"]["derivation"]["args"]
        )
    )

    dump = data["hdwallet"]["Monero"]["dumps"].copy()
    dump.update({
        "entropy": None,
        "strength": None,
        "mnemonic": None,
        "passphrase": None,
        "language": None,
        "seed": None
    })
    assert hdwallet.dumps() == dump

    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Monero"]["dumps"]["derivations"][-1].copy()

    assert hdwallet.dump() == dump

    assert hdwallet.cryptocurrency() == dump["cryptocurrency"]
    assert hdwallet.symbol() == dump["symbol"]
    assert hdwallet.network() == dump["network"]
    assert hdwallet.coin_type() == dump["coin_type"]
    assert hdwallet.entropy() == dump["entropy"]
    assert hdwallet.strength() == dump["strength"]
    assert hdwallet.mnemonic() == dump["mnemonic"]
    assert hdwallet.language() == dump["language"]
    assert hdwallet.seed() ==  dump["seed"]
    assert hdwallet.ecc() == dump["ecc"]
    assert hdwallet.hd() == dump["hd"]
    assert hdwallet.spend_private_key() == dump["spend_private_key"]
    assert hdwallet.view_private_key() == dump["view_private_key"]
    assert hdwallet.spend_public_key() == dump["spend_public_key"]
    assert hdwallet.view_public_key() == dump["view_public_key"]
    assert hdwallet.primary_address() == dump["primary_address"]
    assert hdwallet.integrated_address(
        payment_id="ad17dc6e6793d178"
    ) == dump["integrated_address"]

    assert hdwallet.sub_address() == dump["derivation"]["sub_address"]
