#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.entropies import BIP39Entropy
from hdwallet.hds import HDS


def test_byron_icarus_from_entropy(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Cardano"]["byron-icarus"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Cardano"]["byron-icarus"]["hd"]
        ),
        network=data["hdwallet"]["Cardano"]["byron-icarus"]["network"],
        language=data["hdwallet"]["Cardano"]["byron-icarus"]["language"].lower(),
        cardano_type=data["hdwallet"]["Cardano"]["byron-icarus"]["cardano_type"],
        address_type=cryptocurrency.ADDRESS_TYPES.PUBLIC_KEY
    ).from_entropy(
        entropy=BIP39Entropy(
            entropy=data["hdwallet"]["Cardano"]["byron-icarus"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Cardano"]["derivation"]["name"])(
            **data["hdwallet"]["Cardano"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Cardano"]["byron-icarus"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Cardano"]["byron-icarus"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Cardano"]["byron-icarus"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Cardano"]["byron-icarus"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Cardano"]["byron-icarus"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Cardano"]["byron-icarus"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Cardano"]["byron-icarus"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Cardano"]["byron-icarus"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Cardano"]["byron-icarus"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Cardano"]["byron-icarus"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Cardano"]["byron-icarus"]["hd"]
    assert hdwallet.cardano_type() == data["hdwallet"]["Cardano"]["byron-icarus"]["cardano_type"]
    assert hdwallet.root_xprivate_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["root_xpublic_key"]
    assert hdwallet.root_private_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["root_private_key"]
    assert hdwallet.root_chain_code() == data["hdwallet"]["Cardano"]["byron-icarus"]["root_chain_code"]
    assert hdwallet.root_public_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["root_public_key"]
    assert hdwallet.strict() == data["hdwallet"]["Cardano"]["byron-icarus"]["strict"]

    assert hdwallet.path() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["at"]["path"]
    assert hdwallet.indexes() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["at"]["indexes"]
    assert hdwallet.depth() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["at"]["depth"]

    assert hdwallet.xprivate_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["xprivate_key"]
    assert hdwallet.xpublic_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["xpublic_key"]
    assert hdwallet.private_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["private_key"]
    assert hdwallet.chain_code() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["chain_code"]
    assert hdwallet.public_key() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["public_key"]
    assert hdwallet.hash() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["hash"]
    assert hdwallet.fingerprint() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["fingerprint"]
    assert hdwallet.parent_fingerprint() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["parent_fingerprint"]

    assert hdwallet.address() == data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1]["address"]

    assert hdwallet.dumps() == data["hdwallet"]["Cardano"]["byron-icarus"]

    dump = data["hdwallet"]["Cardano"]["byron-icarus"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Cardano"]["byron-icarus"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
