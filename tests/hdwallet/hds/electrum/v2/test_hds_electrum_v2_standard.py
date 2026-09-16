#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from hdwallet.hds import ElectrumV2HD
from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.derivations import ElectrumDerivation
from hdwallet.consts import (
    PUBLIC_KEY_TYPES, MODES
)


def test_electrum_v2_standard_hd(data):

    electrum_v2_hd: ElectrumV2HD = ElectrumV2HD(
        mode=MODES.STANDARD,
        wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX,
        public_key_type=PUBLIC_KEY_TYPES.UNCOMPRESSED
    )

    electrum_v2_hd.from_seed(
        seed=data["hds"]["Electrum-V2"]["standard"]["seed"]
    )

    assert isinstance(electrum_v2_hd, ElectrumV2HD)

    assert electrum_v2_hd.name() == data["hds"]["Electrum-V2"]["standard"]["name"]
    assert electrum_v2_hd.seed() == data["hds"]["Electrum-V2"]["standard"]["seed"]
    assert electrum_v2_hd.mode() == data["hds"]["Electrum-V2"]["standard"]["mode"]

    assert electrum_v2_hd.master_private_key() == data["hds"]["Electrum-V2"]["standard"]["master-private-key"]
    assert electrum_v2_hd.master_wif() == data["hds"]["Electrum-V2"]["standard"]["master-wif"]
    assert electrum_v2_hd.master_public_key() == data["hds"]["Electrum-V2"]["standard"]["master-public-key"]
    assert electrum_v2_hd.public_key_type() == data["hds"]["Electrum-V2"]["standard"]["public-key-type"]
    assert electrum_v2_hd.wif_type() == data["hds"]["Electrum-V2"]["standard"]["wif-type"]

    electrum_derivation: ElectrumDerivation = ElectrumDerivation(
        change=0, address=0
    )
    electrum_v2_hd.from_derivation(
        derivation=electrum_derivation
    )

    assert electrum_v2_hd.private_key() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["private-key"]
    assert electrum_v2_hd.public_key() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["public-key"]
    assert electrum_v2_hd.wif() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["wif"]
    assert electrum_v2_hd.uncompressed() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["uncompressed"]
    assert electrum_v2_hd.compressed() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["compressed"]
    assert electrum_v2_hd.address() == data["hds"]["Electrum-V2"]["standard"]["derivation"]["address"]
