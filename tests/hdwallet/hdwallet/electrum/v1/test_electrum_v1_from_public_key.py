#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import copy

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.hds import HDS


def test_electrum_v1_from_public_key_compressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V1"]["compressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V1"]["compressed"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V1"]["compressed"]["network"],
        public_key_type=data["hdwallet"]["Electrum-V1"]["compressed"]["public_key_type"]
    ).from_public_key(
        public_key=data["hdwallet"]["Electrum-V1"]["compressed"]["master_public_key"]
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    dump = copy.deepcopy(data["hdwallet"]["Electrum-V1"]["compressed"])
    dump.update({
        "entropy": None,
        "strength": None,
        "mnemonic": None,
        "passphrase": None,
        "language": None,
        "seed": None,
        "master_private_key": None,
        "master_wif": None,
        "wif_type": None
    })

    d_update = {
        "private_key": None,
        "wif": None
    }

    dump["derivations"][0].update(d_update)
    dump["derivations"][1].update(d_update)

    assert hdwallet.dumps() == dump

    dump["derivation"] = dump["derivations"][-1].copy()
    del dump["derivations"]

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
    assert hdwallet.master_private_key() == dump["master_private_key"]
    assert hdwallet.master_wif() == dump["master_wif"]
    assert hdwallet.master_public_key() == dump["master_public_key"]
    assert hdwallet.public_key_type() == dump["public_key_type"]
    assert hdwallet.wif_type() == dump["wif_type"]

    assert hdwallet.private_key() == dump["derivation"]["private_key"]
    assert hdwallet.wif() == dump["derivation"]["wif"]
    assert hdwallet.public_key() == dump["derivation"]["public_key"]
    assert hdwallet.uncompressed() == dump["derivation"]["uncompressed"]
    assert hdwallet.compressed() == dump["derivation"]["compressed"]

    assert hdwallet.address() == dump["derivation"]["address"]


def test_electrum_v1_from_public_key_uncompressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V1"]["uncompressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V1"]["uncompressed"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V1"]["uncompressed"]["network"],
        public_key_type=data["hdwallet"]["Electrum-V1"]["uncompressed"]["public_key_type"]
    ).from_public_key(
        public_key=data["hdwallet"]["Electrum-V1"]["uncompressed"]["master_public_key"]
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    dump = copy.deepcopy(data["hdwallet"]["Electrum-V1"]["uncompressed"])
    dump.update({
        "entropy": None,
        "strength": None,
        "mnemonic": None,
        "passphrase": None,
        "language": None,
        "seed": None,
        "master_private_key": None,
        "master_wif": None,
        "wif_type": None
    })

    d_update = {
        "private_key": None,
        "wif": None
    }

    dump["derivations"][0].update(d_update)
    dump["derivations"][1].update(d_update)

    assert hdwallet.dumps() == dump

    dump["derivation"] = dump["derivations"][-1].copy()
    del dump["derivations"]

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
    assert hdwallet.master_private_key() == dump["master_private_key"]
    assert hdwallet.master_wif() == dump["master_wif"]
    assert hdwallet.master_public_key() == dump["master_public_key"]
    assert hdwallet.public_key_type() == dump["public_key_type"]
    assert hdwallet.wif_type() == dump["wif_type"]

    assert hdwallet.private_key() == dump["derivation"]["private_key"]
    assert hdwallet.wif() == dump["derivation"]["wif"]
    assert hdwallet.public_key() == dump["derivation"]["public_key"]
    assert hdwallet.uncompressed() == dump["derivation"]["uncompressed"]
    assert hdwallet.compressed() == dump["derivation"]["compressed"]

    assert hdwallet.address() == dump["derivation"]["address"]
