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


def test_shelley_ledger_from_mnemonic(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Cardano"]["shelley-ledger"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Cardano"]["shelley-ledger"]["hd"]
        ),
        network=data["hdwallet"]["Cardano"]["shelley-ledger"]["network"],
        language=data["hdwallet"]["Cardano"]["shelley-ledger"]["language"].lower(),
        cardano_type=data["hdwallet"]["Cardano"]["shelley-ledger"]["cardano_type"],
        address_type=cryptocurrency.ADDRESS_TYPES.STAKING
    ).from_mnemonic(
        mnemonic=BIP39Mnemonic(
            mnemonic=data["hdwallet"]["Cardano"]["shelley-ledger"]["mnemonic"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Cardano"]["derivation"]["name"])(
            **data["hdwallet"]["Cardano"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Cardano"]["shelley-ledger"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Cardano"]["shelley-ledger"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Cardano"]["shelley-ledger"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Cardano"]["shelley-ledger"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Cardano"]["shelley-ledger"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Cardano"]["shelley-ledger"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Cardano"]["shelley-ledger"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Cardano"]["shelley-ledger"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Cardano"]["shelley-ledger"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Cardano"]["shelley-ledger"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Cardano"]["shelley-ledger"]["hd"]
    assert hdwallet.cardano_type() == data["hdwallet"]["Cardano"]["shelley-ledger"]["cardano_type"]
    assert hdwallet.root_xprivate_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["root_xpublic_key"]
    assert hdwallet.root_private_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["root_private_key"]
    assert hdwallet.root_chain_code() == data["hdwallet"]["Cardano"]["shelley-ledger"]["root_chain_code"]
    assert hdwallet.root_public_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["root_public_key"]
    assert hdwallet.strict() == data["hdwallet"]["Cardano"]["shelley-ledger"]["strict"]

    assert hdwallet.path() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["at"]["path"]
    assert hdwallet.indexes() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["at"]["indexes"]
    assert hdwallet.depth() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["at"]["depth"]

    assert hdwallet.xprivate_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["xprivate_key"]
    assert hdwallet.xpublic_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["xpublic_key"]
    assert hdwallet.private_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["private_key"]
    assert hdwallet.chain_code() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["chain_code"]
    assert hdwallet.public_key() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["public_key"]
    assert hdwallet.hash() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["hash"]
    assert hdwallet.fingerprint() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["fingerprint"]
    assert hdwallet.parent_fingerprint() == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["parent_fingerprint"]

    assert hdwallet.address(
        address_type=cryptocurrency.ADDRESS_TYPES.STAKING
    ) == data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["address"]

    assert hdwallet.dumps() == data["hdwallet"]["Cardano"]["shelley-ledger"]

    dump = data["hdwallet"]["Cardano"]["shelley-ledger"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
