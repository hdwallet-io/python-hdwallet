#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.entropies import ElectrumV1Entropy
from hdwallet.hds import HDS


def test_electrum_v1_from_entropy_compressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V1"]["compressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V1"]["compressed"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V1"]["compressed"]["network"],
        language=data["hdwallet"]["Electrum-V1"]["compressed"]["language"].lower(),
        public_key_type=data["hdwallet"]["Electrum-V1"]["compressed"]["public_key_type"]
    ).from_entropy(
        entropy=ElectrumV1Entropy(
            entropy=data["hdwallet"]["Electrum-V1"]["compressed"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Electrum-V1"]["compressed"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Electrum-V1"]["compressed"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Electrum-V1"]["compressed"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Electrum-V1"]["compressed"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Electrum-V1"]["compressed"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Electrum-V1"]["compressed"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Electrum-V1"]["compressed"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Electrum-V1"]["compressed"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Electrum-V1"]["compressed"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Electrum-V1"]["compressed"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Electrum-V1"]["compressed"]["hd"]
    assert hdwallet.master_private_key() == data["hdwallet"]["Electrum-V1"]["compressed"]["master_private_key"]
    assert hdwallet.master_wif() == data["hdwallet"]["Electrum-V1"]["compressed"]["master_wif"]
    assert hdwallet.master_public_key() == data["hdwallet"]["Electrum-V1"]["compressed"]["master_public_key"]
    assert hdwallet.public_key_type() == data["hdwallet"]["Electrum-V1"]["compressed"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["Electrum-V1"]["compressed"]["wif_type"]

    assert hdwallet.private_key() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["wif"]
    assert hdwallet.public_key() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["compressed"]

    assert hdwallet.address() == data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1]["address"]
    assert hdwallet.dumps() == data["hdwallet"]["Electrum-V1"]["compressed"]

    dump = data["hdwallet"]["Electrum-V1"]["compressed"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Electrum-V1"]["compressed"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump


def test_electrum_v1_from_entropy_uncompressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V1"]["uncompressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V1"]["uncompressed"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V1"]["uncompressed"]["network"],
        language=data["hdwallet"]["Electrum-V1"]["uncompressed"]["language"].lower(),
        public_key_type=data["hdwallet"]["Electrum-V1"]["uncompressed"]["public_key_type"]
    ).from_entropy(
        entropy=ElectrumV1Entropy(
            entropy=data["hdwallet"]["Electrum-V1"]["uncompressed"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Electrum-V1"]["uncompressed"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["hd"]
    assert hdwallet.master_private_key() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["master_private_key"]
    assert hdwallet.master_wif() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["master_wif"]
    assert hdwallet.master_public_key() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["master_public_key"]
    assert hdwallet.public_key_type() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["wif_type"]

    assert hdwallet.private_key() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["wif"]
    assert hdwallet.public_key() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["compressed"]

    assert hdwallet.address() == data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1]["address"]
    assert hdwallet.dumps() == data["hdwallet"]["Electrum-V1"]["uncompressed"]

    dump = data["hdwallet"]["Electrum-V1"]["uncompressed"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Electrum-V1"]["uncompressed"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
