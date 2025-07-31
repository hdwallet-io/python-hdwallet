#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.hds import HDS


def test_shelley_ledger_from_public_key(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Cardano"]["shelley-ledger"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Cardano"]["shelley-ledger"]["hd"]
        ),
        network=data["hdwallet"]["Cardano"]["shelley-ledger"]["network"],
        cardano_type=data["hdwallet"]["Cardano"]["shelley-ledger"]["cardano_type"],
        address_type=cryptocurrency.ADDRESS_TYPES.STAKING
    ).from_public_key(
        public_key=data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1]["public_key"]
    )

    assert hdwallet.dumps() == None

    dump = data["hdwallet"]["Cardano"]["shelley-ledger"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Cardano"]["shelley-ledger"]["derivations"][-1].copy()

    dump.update({
        "entropy": None,
        "strength": None,
        "mnemonic": None,
        "passphrase": None,
        "language": None,
        "seed": None,
        "root_xprivate_key": None,
        "root_xpublic_key": None,
        "root_private_key": None,
        "root_chain_code": None,
        "root_public_key": None,
        "strict": None
    })

    dump["derivation"].update({
        "xprivate_key": None,
        "xpublic_key": None,
        "private_key": None,
        "chain_code": None,
        "parent_fingerprint": None
    })

    del dump["derivation"]["at"]

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
    assert hdwallet.cardano_type() == dump["cardano_type"]
    assert hdwallet.root_xprivate_key() == dump["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == dump["root_xpublic_key"]
    assert hdwallet.root_private_key() == dump["root_private_key"]
    assert hdwallet.root_chain_code() == dump["root_chain_code"]
    assert hdwallet.root_public_key() == dump["root_public_key"]
    assert hdwallet.strict() == dump["strict"]

    assert hdwallet.xprivate_key() == dump["derivation"]["xprivate_key"]
    assert hdwallet.xpublic_key() == dump["derivation"]["xpublic_key"]
    assert hdwallet.private_key() == dump["derivation"]["private_key"]
    assert hdwallet.chain_code() == dump["derivation"]["chain_code"]
    assert hdwallet.public_key() == dump["derivation"]["public_key"]
    assert hdwallet.hash() == dump["derivation"]["hash"]
    assert hdwallet.fingerprint() == dump["derivation"]["fingerprint"]
    assert hdwallet.parent_fingerprint() == dump["derivation"]["parent_fingerprint"]

    assert hdwallet.address(
        address_type=cryptocurrency.ADDRESS_TYPES.STAKING
    ) == dump["derivation"]["address"]
