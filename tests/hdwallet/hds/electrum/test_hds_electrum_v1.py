#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.hds import ElectrumV1HD
from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import ElectrumDerivation
from hdwallet.consts import PUBLIC_KEY_TYPES


def test_electrum_v1_hd(data):

    electrum_v1_hd: ElectrumV1HD = ElectrumV1HD(
        public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
        wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX
    )

    electrum_v1_hd.from_seed(
        seed=data["hds"]["Electrum-V1"]["seed"]
    )

    assert isinstance(electrum_v1_hd, ElectrumV1HD)

    assert electrum_v1_hd.name() == data["hds"]["Electrum-V1"]["name"]
    assert electrum_v1_hd.seed() == data["hds"]["Electrum-V1"]["seed"]

    assert electrum_v1_hd.master_private_key() == data["hds"]["Electrum-V1"]["master-private-key"]
    assert electrum_v1_hd.master_wif() == data["hds"]["Electrum-V1"]["master-wif"]
    assert electrum_v1_hd.master_public_key() == data["hds"]["Electrum-V1"]["master-public-key"]
    assert electrum_v1_hd.public_key_type() == data["hds"]["Electrum-V1"]["public-key-type"]
    assert electrum_v1_hd.wif_type() == data["hds"]["Electrum-V1"]["wif-type"]

    electrum_derivation: ElectrumDerivation = ElectrumDerivation(
        change=0, address=0
    )
    electrum_v1_hd.from_derivation(
        derivation=electrum_derivation
    )

    assert electrum_v1_hd.private_key() == data["hds"]["Electrum-V1"]["derivation"]["private-key"]
    assert electrum_v1_hd.public_key() == data["hds"]["Electrum-V1"]["derivation"]["public-key"]
    assert electrum_v1_hd.wif() == data["hds"]["Electrum-V1"]["derivation"]["wif"]
    assert electrum_v1_hd.uncompressed() == data["hds"]["Electrum-V1"]["derivation"]["uncompressed"]
    assert electrum_v1_hd.compressed() == data["hds"]["Electrum-V1"]["derivation"]["compressed"]
    assert electrum_v1_hd.address() == data["hds"]["Electrum-V1"]["derivation"]["address"]
