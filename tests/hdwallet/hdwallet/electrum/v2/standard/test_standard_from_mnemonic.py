#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import CRYPTOCURRENCIES
from hdwallet.derivations import DERIVATIONS
from hdwallet.mnemonics import ElectrumV2Mnemonic
from hdwallet.hds import HDS


def test_standard_from_mnemonic(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["Electrum-V2"]["standard"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["Electrum-V2"]["standard"]["hd"]
        ),
        network=data["hdwallet"]["Electrum-V2"]["standard"]["network"],
        language=data["hdwallet"]["Electrum-V2"]["standard"]["language"].lower(),
        mnemonic_type=data["hdwallet"]["Electrum-V2"]["standard"]["mnemonic_type"],
        mode=data["hdwallet"]["Electrum-V2"]["standard"]["mode"],
        public_key_type=data["hdwallet"]["Electrum-V2"]["standard"]["public_key_type"]
    ).from_mnemonic(
        mnemonic=ElectrumV2Mnemonic(
            mnemonic=data["hdwallet"]["Electrum-V2"]["standard"]["mnemonic"],
            mnemonic_type=data["hdwallet"]["Electrum-V2"]["standard"]["mnemonic_type"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["Electrum-V1"]["derivation"]["name"])(
            **data["hdwallet"]["Electrum-V1"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["Electrum-V2"]["standard"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["Electrum-V2"]["standard"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["Electrum-V2"]["standard"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["Electrum-V2"]["standard"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["Electrum-V2"]["standard"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["Electrum-V2"]["standard"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["Electrum-V2"]["standard"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["Electrum-V2"]["standard"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["Electrum-V2"]["standard"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["Electrum-V2"]["standard"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["Electrum-V2"]["standard"]["hd"]
    assert hdwallet.master_private_key() == data["hdwallet"]["Electrum-V2"]["standard"]["master_private_key"]
    assert hdwallet.master_wif() == data["hdwallet"]["Electrum-V2"]["standard"]["master_wif"]
    assert hdwallet.master_public_key() == data["hdwallet"]["Electrum-V2"]["standard"]["master_public_key"]
    assert hdwallet.public_key_type() == data["hdwallet"]["Electrum-V2"]["standard"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["Electrum-V2"]["standard"]["wif_type"]

    assert hdwallet.private_key() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["wif"]
    assert hdwallet.public_key() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["compressed"]

    assert hdwallet.address() == data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1]["address"]
    assert hdwallet.dumps() == data["hdwallet"]["Electrum-V2"]["standard"]

    dump = data["hdwallet"]["Electrum-V2"]["standard"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["Electrum-V2"]["standard"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
