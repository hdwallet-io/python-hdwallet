#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.mnemonics import BIP39Mnemonic
from hdwallet.hds import HDS


def test_byron_ledger_from_mnemonic(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Cardano"]["byron-ledger"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Cardano"]["byron-ledger"]["hd"]
        ),
        network=data["hdwallet"]["Cardano"]["byron-ledger"]["network"],
        language=data["hdwallet"]["Cardano"]["byron-ledger"]["language"].lower(),
        cardano_type=data["hdwallet"]["Cardano"]["byron-ledger"]["cardano_type"],
        address_type=cryptocurrency.ADDRESS_TYPES.PUBLIC_KEY
    ).from_mnemonic(
        mnemonic=BIP39Mnemonic(
            mnemonic=data["hdwallet"]["Cardano"]["byron-ledger"]["mnemonic"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Cardano"]["derivation"]["name"])(
            **data["hdwallet"]["Cardano"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Cardano"]["byron-ledger"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Cardano"]["byron-ledger"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Cardano"]["byron-ledger"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Cardano"]["byron-ledger"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Cardano"]["byron-ledger"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Cardano"]["byron-ledger"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Cardano"]["byron-ledger"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Cardano"]["byron-ledger"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Cardano"]["byron-ledger"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Cardano"]["byron-ledger"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Cardano"]["byron-ledger"]["hd"]
    assert hdwallet.cardano_type() == data["hdwallet"]["Cardano"]["byron-ledger"]["cardano_type"]
    assert hdwallet.root_xprivate_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["root_xpublic_key"]
    assert hdwallet.root_private_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["root_private_key"]
    assert hdwallet.root_chain_code() == data["hdwallet"]["Cardano"]["byron-ledger"]["root_chain_code"]
    assert hdwallet.root_public_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["root_public_key"]
    assert hdwallet.strict() == data["hdwallet"]["Cardano"]["byron-ledger"]["strict"]

    assert hdwallet.path() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["at"]["path"]
    assert hdwallet.indexes() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["at"]["indexes"]
    assert hdwallet.depth() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["at"]["depth"]

    assert hdwallet.xprivate_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["xprivate_key"]
    assert hdwallet.xpublic_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["xpublic_key"]
    assert hdwallet.private_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["private_key"]
    assert hdwallet.chain_code() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["chain_code"]
    assert hdwallet.public_key() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["public_key"]
    assert hdwallet.hash() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["hash"]
    assert hdwallet.fingerprint() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["fingerprint"]
    assert hdwallet.parent_fingerprint() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["parent_fingerprint"]

    assert hdwallet.address() == data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1]["address"]

    assert hdwallet.dumps() == data["hdwallet"]["Cardano"]["byron-ledger"]

    dump = data["hdwallet"]["Cardano"]["byron-ledger"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Cardano"]["byron-ledger"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
