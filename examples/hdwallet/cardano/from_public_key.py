#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.cryptocurrencies import Cardano as Cryptocurrency
from hdwallet.hds import CardanoHD

import json


hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=CardanoHD,
    cardano_type=Cryptocurrency.TYPES.SHELLEY_LEDGER,
    address_type=Cryptocurrency.ADDRESS_TYPES.STAKING
).from_public_key(
    public_key="00c76d02311731bdca7afe7907f2f3b53383d43f278d8c22abb73c17d417d37cf1"
)

print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))

# print("Cryptocurrency:", hdwallet.cryptocurrency())
# print("Symbol:", hdwallet.symbol())
# print("Network:", hdwallet.network())
# print("Coin Type:", hdwallet.coin_type())
# print("ECC:", hdwallet.ecc())
# print("HD:", hdwallet.hd())
# print("Cardano Type:", hdwallet.cardano_type())
# print("Semantic:", hdwallet.semantic())
# print("Public Key Type:", hdwallet.public_key_type())
# print("Public Key:", hdwallet.public_key())
# print("Uncompressed:", hdwallet.uncompressed())
# print("Compressed:", hdwallet.compressed())
# print("Hash:", hdwallet.hash())
# print("Fingerprint:", hdwallet.fingerprint())
# print("Address:", hdwallet.address())
