#!/usr/bin/env python3

from hdwallet.entropies.bip39 import (
    BIP39Entropy, BIP39_ENTROPY_STRENGTHS
)
from hdwallet.mnemonics.bip39 import (
    BIP39Mnemonic, BIP39_MNEMONIC_LANGUAGES
)
from hdwallet.seeds.cardano import CardanoSeed
from hdwallet.cryptocurrencies import Cardano
from hdwallet.hds import CardanoHD
from hdwallet.derivations import BIP44Derivation


# Generate BIP39 entropy
entropy: str = BIP39Entropy.generate(
    strength=BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT
)
bip39_entropy: BIP39Entropy = BIP39Entropy(entropy=entropy)
print("BIP39 Entropy:", bip39_entropy.entropy())
print("BIP39 Strength:", bip39_entropy.strength())

# Get BIP39 mnemonic
mnemonic: str = BIP39Mnemonic.from_entropy(
    entropy=bip39_entropy, language=BIP39_MNEMONIC_LANGUAGES.CHINESE_TRADITIONAL
)
bip39_mnemonic: BIP39Mnemonic = BIP39Mnemonic(mnemonic=mnemonic)
print("BIP39 Mnemonic:", bip39_mnemonic.mnemonic())
print("BIP39 Language:", bip39_mnemonic.language())
print("BIP39 Words:", bip39_mnemonic.words())

# Initialize Byron-Icarus Cardano HD
cardano_hd: CardanoHD = CardanoHD(
    cardano_type=Cardano.TYPES.BYRON_ICARUS
)

# Get Byron-Icarus Cardano seed
seed: str = CardanoSeed.from_mnemonic(
    mnemonic=bip39_mnemonic, cardano_type=Cardano.TYPES.BYRON_ICARUS
)
cardano_seed: CardanoSeed = CardanoSeed(seed=seed, cardano_type=Cardano.TYPES.BYRON_ICARUS)

# Update Byron-Icarus Cardano HD root keys from seed
cardano_hd.from_seed(
    seed=cardano_seed
)

# Dump root keys
print("Byron-Icarus Seed:", cardano_seed.seed())
print("Byron-Icarus Root XPrivate Key:", cardano_hd.root_xprivate_key())
print("Byron-Icarus Root XPublic Key:", cardano_hd.root_xpublic_key())
print("Byron-Icarus Root Chain Code:", cardano_hd.root_chain_code())
print("Byron-Icarus Root Private Key:", cardano_hd.root_private_key())
print("Byron-Icarus Root Public Key:", cardano_hd.root_public_key())

# Initialize BIP44 derivation
bip44_derivation: BIP44Derivation = BIP44Derivation(
    coin_type=Cardano.COIN_TYPE
)
bip44_derivation.from_account(account=0)
bip44_derivation.from_change(change="external-chain")
bip44_derivation.from_address(address=0)

# Update current Byron-Icarus Cardano HD derivation
cardano_hd.from_derivation(
    derivation=bip44_derivation
)

# Dump derived keys
print("Byron-Icarus XPrivate Key:", cardano_hd.xprivate_key())
print("Byron-Icarus XPublic Key:", cardano_hd.xpublic_key())
print("Byron-Icarus Private Key:", cardano_hd.private_key())
print("Byron-Icarus Chain Code:", cardano_hd.chain_code())
print("Byron-Icarus Public Key:", cardano_hd.public_key())
print("Byron-Icarus Depth:", cardano_hd.depth())
print("Byron-Icarus Path:", cardano_hd.path())
print("Byron-Icarus Index:", cardano_hd.index())
print("Byron-Icarus Indexes:", cardano_hd.indexes())
print("Byron-Icarus Fingerprint:", cardano_hd.fingerprint())
print("Byron-Icarus Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Byron-Icarus Address:", cardano_hd.address())
