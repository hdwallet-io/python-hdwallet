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


def test_bip86_from_entropy_compressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["BIP86"]["compressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["BIP86"]["compressed"]["hd"]
        ),
        network=data["hdwallet"]["BIP86"]["compressed"]["network"],
        language=data["hdwallet"]["BIP86"]["compressed"]["language"].lower(),
        public_key_type=data["hdwallet"]["BIP86"]["compressed"]["public_key_type"]
    ).from_entropy(
        entropy=BIP39Entropy(
            entropy=data["hdwallet"]["BIP86"]["compressed"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["BIP86"]["derivation"]["name"])(
            **data["hdwallet"]["BIP86"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["BIP86"]["compressed"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["BIP86"]["compressed"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["BIP86"]["compressed"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["BIP86"]["compressed"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["BIP86"]["compressed"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["BIP86"]["compressed"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["BIP86"]["compressed"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["BIP86"]["compressed"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["BIP86"]["compressed"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["BIP86"]["compressed"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["BIP86"]["compressed"]["hd"]
    assert hdwallet.root_xprivate_key() == data["hdwallet"]["BIP86"]["compressed"]["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == data["hdwallet"]["BIP86"]["compressed"]["root_xpublic_key"]
    assert hdwallet.root_private_key() == data["hdwallet"]["BIP86"]["compressed"]["root_private_key"]
    assert hdwallet.root_wif() == data["hdwallet"]["BIP86"]["compressed"]["root_wif"]
    assert hdwallet.root_chain_code() == data["hdwallet"]["BIP86"]["compressed"]["root_chain_code"]
    assert hdwallet.root_public_key() == data["hdwallet"]["BIP86"]["compressed"]["root_public_key"]
    assert hdwallet.strict() == data["hdwallet"]["BIP86"]["compressed"]["strict"]
    assert hdwallet.public_key_type() == data["hdwallet"]["BIP86"]["compressed"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["BIP86"]["compressed"]["wif_type"]

    assert hdwallet.path() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["at"]["path"]
    assert hdwallet.indexes() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["at"]["indexes"]
    assert hdwallet.depth() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["at"]["depth"]

    assert hdwallet.xprivate_key() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["xprivate_key"]
    assert hdwallet.xpublic_key() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["xpublic_key"]
    assert hdwallet.private_key() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["wif"]
    assert hdwallet.chain_code() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["chain_code"]
    assert hdwallet.public_key() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["compressed"]
    assert hdwallet.hash() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["hash"]
    assert hdwallet.fingerprint() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["fingerprint"]
    assert hdwallet.parent_fingerprint() == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["parent_fingerprint"]

    assert hdwallet.address(
        address="P2TR",
        hrp=cryptocurrency.NETWORKS.MAINNET.HRP,
        witness_version=cryptocurrency.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR
    ) == data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1]["address"]

    assert hdwallet.dumps() == data["hdwallet"]["BIP86"]["compressed"]

    dump = data["hdwallet"]["BIP86"]["compressed"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["BIP86"]["compressed"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump


def test_bip86_from_entropy_uncompressed(data):

    cryptocurrency = CRYPTOCURRENCIES.cryptocurrency(
        data["hdwallet"]["BIP86"]["uncompressed"]["cryptocurrency"]
    )
    hdwallet: HDWallet = HDWallet(
        cryptocurrency=cryptocurrency,
        hd=HDS.hd(
            data["hdwallet"]["BIP86"]["uncompressed"]["hd"]
        ),
        network=data["hdwallet"]["BIP86"]["uncompressed"]["network"],
        language=data["hdwallet"]["BIP86"]["uncompressed"]["language"].lower(),
        public_key_type=data["hdwallet"]["BIP86"]["uncompressed"]["public_key_type"]
    ).from_entropy(
        entropy=BIP39Entropy(
            entropy=data["hdwallet"]["BIP86"]["uncompressed"]["entropy"]
        )
    ).from_derivation(
        derivation=DERIVATIONS.derivation(data["hdwallet"]["BIP86"]["derivation"]["name"])(
            **data["hdwallet"]["BIP86"]["derivation"]["args"]
        )
    )

    assert hdwallet.cryptocurrency() == data["hdwallet"]["BIP86"]["uncompressed"]["cryptocurrency"]
    assert hdwallet.symbol() == data["hdwallet"]["BIP86"]["uncompressed"]["symbol"]
    assert hdwallet.network() == data["hdwallet"]["BIP86"]["uncompressed"]["network"]
    assert hdwallet.coin_type() == data["hdwallet"]["BIP86"]["uncompressed"]["coin_type"]
    assert hdwallet.entropy() == data["hdwallet"]["BIP86"]["uncompressed"]["entropy"]
    assert hdwallet.strength() == data["hdwallet"]["BIP86"]["uncompressed"]["strength"]
    assert hdwallet.mnemonic() == data["hdwallet"]["BIP86"]["uncompressed"]["mnemonic"]
    assert hdwallet.language() == data["hdwallet"]["BIP86"]["uncompressed"]["language"]
    assert hdwallet.seed() ==  data["hdwallet"]["BIP86"]["uncompressed"]["seed"]
    assert hdwallet.ecc() == data["hdwallet"]["BIP86"]["uncompressed"]["ecc"]
    assert hdwallet.hd() == data["hdwallet"]["BIP86"]["uncompressed"]["hd"]
    assert hdwallet.root_xprivate_key() == data["hdwallet"]["BIP86"]["uncompressed"]["root_xprivate_key"]
    assert hdwallet.root_xpublic_key() == data["hdwallet"]["BIP86"]["uncompressed"]["root_xpublic_key"]
    assert hdwallet.root_private_key() == data["hdwallet"]["BIP86"]["uncompressed"]["root_private_key"]
    assert hdwallet.root_wif() == data["hdwallet"]["BIP86"]["uncompressed"]["root_wif"]
    assert hdwallet.root_chain_code() == data["hdwallet"]["BIP86"]["uncompressed"]["root_chain_code"]
    assert hdwallet.root_public_key() == data["hdwallet"]["BIP86"]["uncompressed"]["root_public_key"]
    assert hdwallet.strict() == data["hdwallet"]["BIP86"]["uncompressed"]["strict"]
    assert hdwallet.public_key_type() == data["hdwallet"]["BIP86"]["uncompressed"]["public_key_type"]
    assert hdwallet.wif_type() == data["hdwallet"]["BIP86"]["uncompressed"]["wif_type"]

    assert hdwallet.xprivate_key() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["xprivate_key"]
    assert hdwallet.xpublic_key() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["xpublic_key"]
    assert hdwallet.private_key() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["private_key"]
    assert hdwallet.wif() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["wif"]
    assert hdwallet.chain_code() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["chain_code"]
    assert hdwallet.public_key() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["public_key"]
    assert hdwallet.uncompressed() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["uncompressed"]
    assert hdwallet.compressed() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["compressed"]
    assert hdwallet.hash() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["hash"]
    assert hdwallet.fingerprint() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["fingerprint"]
    assert hdwallet.parent_fingerprint() == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["parent_fingerprint"]

    assert hdwallet.address(
        address="P2TR",
        hrp=cryptocurrency.NETWORKS.MAINNET.HRP,
        witness_version=cryptocurrency.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR
    ) == data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1]["address"]

    assert hdwallet.dumps() == data["hdwallet"]["BIP86"]["uncompressed"]

    dump = data["hdwallet"]["BIP86"]["uncompressed"].copy()
    del dump["derivations"]
    dump["derivation"] = data["hdwallet"]["BIP86"]["uncompressed"]["derivations"][-1].copy()
    assert hdwallet.dump() == dump
