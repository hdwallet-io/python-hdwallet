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


def test_electrum_v2_segwit_hd(data):

    electrum_v2_hd: ElectrumV2HD = ElectrumV2HD(
        mode=MODES.SEGWIT,
        public_key_type=PUBLIC_KEY_TYPES.UNCOMPRESSED,
        wif_prefix = Cryptocurrency.NETWORKS.MAINNET.WIF_PREFIX
    )

    electrum_v2_hd.from_seed(
        seed=data["hds"]["Electrum-V2"]["segwit"]["seed"]
    )

    assert isinstance(electrum_v2_hd, ElectrumV2HD)

    assert electrum_v2_hd.name() == data["hds"]["Electrum-V2"]["segwit"]["name"]
    assert electrum_v2_hd.seed() == data["hds"]["Electrum-V2"]["segwit"]["seed"]
    assert electrum_v2_hd.mode() == data["hds"]["Electrum-V2"]["segwit"]["mode"]

    assert electrum_v2_hd.master_private_key() == data["hds"]["Electrum-V2"]["segwit"]["master-private-key"]
    assert electrum_v2_hd.master_wif() == data["hds"]["Electrum-V2"]["segwit"]["master-wif"]
    assert electrum_v2_hd.master_public_key() == data["hds"]["Electrum-V2"]["segwit"]["master-public-key"]
    assert electrum_v2_hd.public_key_type() == data["hds"]["Electrum-V2"]["segwit"]["public-key-type"]
    assert electrum_v2_hd.wif_type() == data["hds"]["Electrum-V2"]["segwit"]["wif-type"]

    electrum_derivation: ElectrumDerivation = ElectrumDerivation(
        change=0, address=0
    )
    electrum_v2_hd.from_derivation(
        derivation=electrum_derivation
    )

    assert electrum_v2_hd.private_key() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["private-key"]
    assert electrum_v2_hd.public_key() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["public-key"]
    assert electrum_v2_hd.wif() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["wif"]
    assert electrum_v2_hd.uncompressed() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["uncompressed"]
    assert electrum_v2_hd.compressed() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["compressed"]
    assert electrum_v2_hd.address() == data["hds"]["Electrum-V2"]["segwit"]["derivation"]["address"]
