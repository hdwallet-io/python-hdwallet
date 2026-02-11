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
from hdwallet.derivations import CustomDerivation


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

# Initialize Byron-Legacy Cardano HD
cardano_hd: CardanoHD = CardanoHD(
    cardano_type=Cardano.TYPES.BYRON_LEGACY
)

# Get Byron-Legacy Cardano seed
seed: str = CardanoSeed.from_mnemonic(
    mnemonic=bip39_mnemonic, cardano_type=Cardano.TYPES.BYRON_LEGACY
)
cardano_seed: CardanoSeed = CardanoSeed(seed=seed, cardano_type=Cardano.TYPES.BYRON_LEGACY)

# Update Byron-Legacy Cardano HD root keys from seed
cardano_hd.from_seed(
    seed=cardano_seed
)

# Dump root keys
print("Byron-Legacy Seed:", cardano_seed.seed())
print("Byron-Legacy Root XPrivate Key:", cardano_hd.root_xprivate_key())
print("Byron-Legacy Root XPublic Key:", cardano_hd.root_xpublic_key())
print("Byron-Legacy Root Chain Code:", cardano_hd.root_chain_code())
print("Byron-Legacy Root Private Key:", cardano_hd.root_private_key())
print("Byron-Legacy Root Public Key:", cardano_hd.root_public_key())

# Initialize Custom derivation
custom_derivation: CustomDerivation = CustomDerivation(
    path="m/0'/0'"
)

# Update current Byron-Legacy Cardano HD derivation
cardano_hd.from_derivation(
    derivation=custom_derivation
)

# Dump derived keys
print("Byron-Legacy XPrivate Key:", cardano_hd.xprivate_key())
print("Byron-Legacy XPublic Key:", cardano_hd.xpublic_key())
print("Byron-Legacy Private Key:", cardano_hd.private_key())
print("Byron-Legacy Chain Code:", cardano_hd.chain_code())
print("Byron-Legacy Public Key:", cardano_hd.public_key())
print("Byron-Legacy Depth:", cardano_hd.depth())
print("Byron-Legacy Path:", cardano_hd.path())
print("Byron-Legacy Index:", cardano_hd.index())
print("Byron-Legacy Indexes:", cardano_hd.indexes())
print("Byron-Legacy Fingerprint:", cardano_hd.fingerprint())
print("Byron-Legacy Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Byron-Legacy Address:", cardano_hd.address())
