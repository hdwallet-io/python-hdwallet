#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.seeds import CardanoSeed
from hdwallet.cryptocurrencies import Cardano as Cryptocurrency
from hdwallet.hds import CardanoHD
from hdwallet.derivations import (
    CIP1852Derivation, ROLES
)

import json


hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=CardanoHD,
    cardano_type=Cryptocurrency.TYPES.SHELLEY_ICARUS,
    address_type=Cryptocurrency.ADDRESS_TYPES.PAYMENT,
    staking_public_key="00f06973be3a2b8d74086283e18176b6b4b5bd28da78c264cd65ad146126f8240e",
    passphrase="talonlab"
).from_seed(
    seed=CardanoSeed(
        seed="fca87b68fdffa968895901c894f678f6",
        cardano_type=Cryptocurrency.TYPES.SHELLEY_ICARUS,
    )
).from_derivation(
    derivation=CIP1852Derivation(
        coin_type=Cryptocurrency.COIN_TYPE,
        account=0,
        role=ROLES.EXTERNAL_CHAIN,
        address=(6, 8)
    )
)

# print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))
print(json.dumps(hdwallet.dumps(exclude={"indexes"}), indent=4, ensure_ascii=False))

# print("Cryptocurrency:", hdwallet.cryptocurrency())
# print("Symbol:", hdwallet.symbol())
# print("Network:", hdwallet.network())
# print("Coin Type:", hdwallet.coin_type())
# print("Seed:", hdwallet.seed())
# print("ECC:", hdwallet.ecc())
# print("HD:", hdwallet.hd())
# print("Cardano Type:", hdwallet.cardano_type())
# print("Semantic:", hdwallet.semantic())
# print("Root XPrivate Key:", hdwallet.root_xprivate_key())
# print("Root XPublic Key:", hdwallet.root_xpublic_key())
# print("Root Private Key:", hdwallet.root_private_key())
# print("Root Chain Code:", hdwallet.root_chain_code())
# print("Root Public Key:", hdwallet.root_public_key())
# print("Strict:", hdwallet.strict())
# print("Path:", hdwallet.path())
# print("Depth:", hdwallet.depth())
# print("Indexes:", hdwallet.indexes())
# print("Index:", hdwallet.index())
# print("XPrivate Key:", hdwallet.xprivate_key())
# print("XPublic Key:", hdwallet.xpublic_key())
# print("Private Key:", hdwallet.private_key())
# print("Chain Code:", hdwallet.chain_code())
# print("Public Key:", hdwallet.public_key())
# print("Hash:", hdwallet.hash())
# print("Fingerprint:", hdwallet.fingerprint())
# print("Parent Fingerprint:", hdwallet.parent_fingerprint())
# print("Address:", hdwallet.address())
