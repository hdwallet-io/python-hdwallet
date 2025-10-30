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
from hdwallet.derivations import (
    CIP1852Derivation, ROLES
)

# Generate BIP39 entropy
entropy: str = BIP39Entropy.generate(
    strength=BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT
)
bip39_entropy: BIP39Entropy = BIP39Entropy(entropy=entropy)
print("BIP39 Entropy:", bip39_entropy.entropy())
print("BIP39 Strength:", bip39_entropy.strength())

# Get BIP39 mnemonic
mnemonic: str = BIP39Mnemonic.from_entropy(
    entropy=bip39_entropy, language=BIP39_MNEMONIC_LANGUAGES.CZECH
)
bip39_mnemonic: BIP39Mnemonic = BIP39Mnemonic(mnemonic=mnemonic)
print("BIP39 Mnemonic:", bip39_mnemonic.mnemonic())
print("BIP39 Language:", bip39_mnemonic.language())
print("BIP39 Words:", bip39_mnemonic.words())

# Initialize Shelley-Icarus Cardano HD
cardano_hd: CardanoHD = CardanoHD(
    cardano_type=Cardano.TYPES.SHELLEY_ICARUS
)

# Get Shelley-Icarus Cardano seed
seed: str = CardanoSeed.from_mnemonic(
    mnemonic=bip39_mnemonic, cardano_type=Cardano.TYPES.SHELLEY_ICARUS
)
cardano_seed: CardanoSeed = CardanoSeed(seed=seed, cardano_type=Cardano.TYPES.SHELLEY_ICARUS)

# Update Shelley-Icarus Cardano HD root keys from seed
cardano_hd.from_seed(
    seed=cardano_seed
)

# Dump root keys
print("Shelley-Icarus Seed:", cardano_seed.seed())
print("Shelley-Icarus Root XPrivate Key:", cardano_hd.root_xprivate_key())
print("Shelley-Icarus Root XPublic Key:", cardano_hd.root_xpublic_key())
print("Shelley-Icarus Root Chain Code:", cardano_hd.root_chain_code())
print("Shelley-Icarus Root Private Key:", cardano_hd.root_private_key())
print("Shelley-Icarus Root Public Key:", cardano_hd.root_public_key())

# Initialize CIP1852 derivation
cip1852_derivation: CIP1852Derivation = CIP1852Derivation(
    coin_type=Cardano.COIN_TYPE, role=ROLES.STAKING_KEY  # https://cips.cardano.org/cips/cip11
)
cip1852_derivation.from_account(account=0)
cip1852_derivation.from_address(address=0)

# Update current Shelley-Icarus Cardano HD derivation
cardano_hd.from_derivation(
    derivation=cip1852_derivation
)

# Dump derived staking keys
print("Staking Shelley-Icarus XPrivate Key:", cardano_hd.xprivate_key())
print("Staking Shelley-Icarus XPublic Key:", cardano_hd.xpublic_key())
print("Staking Shelley-Icarus Private Key:", cardano_hd.private_key())
print("Staking Shelley-Icarus Chain Code:", cardano_hd.chain_code())
staking_public_key: str = cardano_hd.public_key()
print("Staking Shelley-Icarus Public Key:", staking_public_key)
print("Staking Shelley-Icarus Depth:", cardano_hd.depth())
print("Staking Shelley-Icarus Path:", cardano_hd.path())
print("Staking Shelley-Icarus Index:", cardano_hd.index())
print("Staking Shelley-Icarus Indexes:", cardano_hd.indexes())
print("Staking Shelley-Icarus Fingerprint:", cardano_hd.fingerprint())
print("Staking Shelley-Icarus Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Staking Shelley-Icarus Address:", cardano_hd.address(address_type="staking"))

# Change CIP1852 Derivation role into external-chain
cip1852_derivation.from_role(
    role=ROLES.EXTERNAL_CHAIN
)

# Update current Shelley-Icarus Cardano HD derivation
cardano_hd.update_derivation(
    derivation=cip1852_derivation
)

# Dump derived keys
print("Shelley-Icarus XPrivate Key:", cardano_hd.xprivate_key())
print("Shelley-Icarus XPublic Key:", cardano_hd.xpublic_key())
print("Shelley-Icarus Private Key:", cardano_hd.private_key())
print("Shelley-Icarus Chain Code:", cardano_hd.chain_code())
print("Shelley-Icarus Public Key:", cardano_hd.public_key())
print("Shelley-Icarus Depth:", cardano_hd.depth())
print("Shelley-Icarus Path:", cardano_hd.path())
print("Shelley-Icarus Index:", cardano_hd.index())
print("Shelley-Icarus Indexes:", cardano_hd.indexes())
print("Shelley-Icarus Fingerprint:", cardano_hd.fingerprint())
print("Shelley-Icarus Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Shelley-Icarus Address:", cardano_hd.address(
    address_type="payment", staking_public_key=staking_public_key
))
