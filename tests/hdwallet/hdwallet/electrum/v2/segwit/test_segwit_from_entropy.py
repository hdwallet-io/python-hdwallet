#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.entropies import ElectrumV2Entropy
from hdwallet.hds import HDS


def test_segiwt_from_entropy(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V2"]["segwit"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V2"]["segwit"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V2"]["segwit"]["network"],
        language=data["hdwallet"]["Electrum-V2"]["segwit"]["language"].lower(),
        mnemonic_type=data["hdwallet"]["Electrum-V2"]["segwit"]["mnemonic_type"],
        mode=data["hdwallet"]["Electrum-V2"]["segwit"]["mode"],
        public_key_type=data["hdwallet"]["Electrum-V2"]["segwit"]["public_key_type"]
    ).from_entropy(
        entropy=ElectrumV2Entropy(
            entropy=data["hdwallet"]["Electrum-V2"]["segwit"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Electrum-V2"]["segwit"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Electrum-V2"]["segwit"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Electrum-V2"]["segwit"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Electrum-V2"]["segwit"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Electrum-V2"]["segwit"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Electrum-V2"]["segwit"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Electrum-V2"]["segwit"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Electrum-V2"]["segwit"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Electrum-V2"]["segwit"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Electrum-V2"]["segwit"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Electrum-V2"]["segwit"]["hd"]
    assert hdwallet.master_private_key() == data["hdwallet"]["Electrum-V2"]["segwit"]["master_private_key"]
    assert hdwallet.master_wif() == data["hdwallet"]["Electrum-V2"]["segwit"]["master_wif"]
    assert hdwallet.master_public_key() == data["hdwallet"]["Electrum-V2"]["segwit"]["master_public_key"]
    assert hdwallet.public_key_type() == data["hdwallet"]["Electrum-V2"]["segwit"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["Electrum-V2"]["segwit"]["wif_type"]

    assert hdwallet.private_key() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["wif"]
    assert hdwallet.public_key() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["compressed"]

    assert hdwallet.address() == data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1]["address"]
    assert hdwallet.dumps() == data["hdwallet"]["Electrum-V2"]["segwit"]

    dump = data["hdwallet"]["Electrum-V2"]["segwit"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Electrum-V2"]["segwit"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
