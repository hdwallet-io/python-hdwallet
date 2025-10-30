#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.mnemonics import BIP39Mnemonic
from hdwallet.seeds import BIP39Seed, SLIP39Seed
from hdwallet.cryptocurrencies import Ethereum as Cryptocurrency
from hdwallet.hds import BIP44HD
from hdwallet.derivations import (
    BIP44Derivation, CHANGES
)

import json

# 24-words mnemonic phrase
MNEMONIC: str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " \
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

# Initialize Ethereum HDWallet using BIP-39 Entropy as Seed
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP44HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    passphrase=None
).from_seed(   # Get Ethereum HDWallet from seed
    seed=SLIP39Seed(
        seed=BIP39Mnemonic.decode(mnemonic=MNEMONIC)  # Use decoded mnemonic (entropy) directly as seed
    )
).from_derivation(  # Drive from BIP44 derivation
    derivation=BIP44Derivation(
        coin_type=Cryptocurrency.COIN_TYPE,
        account=0,
        change=CHANGES.EXTERNAL_CHAIN,
        address=0
    )
)

# Same address of Brave crypto wallets extension
# print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))
print(f"Path: {hdwallet.path()}")
print(f"Address: {hdwallet.address()}")

assert hdwallet.address() == "0xACA6302EcBde40120cb8A08361D8BD461282Bd18"

# Initialize Ethereum HDWallet using BIP-39 Seed (confirmed current Brave Wallet behavior)
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP44HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    passphrase=None
).from_seed(   # Get Ethereum HDWallet from seed
    seed=BIP39Seed.from_mnemonic(mnemonic=MNEMONIC)  # Use BIP-39 encoded mnemonic as seed
).from_derivation(  # Drive from BIP44 derivation
    derivation=BIP44Derivation(
        coin_type=Cryptocurrency.COIN_TYPE,
        account=0,
        change=CHANGES.EXTERNAL_CHAIN,
        address=0
    )
)

# print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))
print(f"Address: {hdwallet.address()}")
assert hdwallet.address() == "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"
