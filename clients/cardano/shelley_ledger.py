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

# Initialize Shelley-Ledger Cardano HD
cardano_hd: CardanoHD = CardanoHD(
    cardano_type=Cardano.TYPES.SHELLEY_LEDGER
)

# Get Shelley-Ledger Cardano seed
seed: str = CardanoSeed.from_mnemonic(
    mnemonic=bip39_mnemonic, cardano_type=Cardano.TYPES.SHELLEY_LEDGER
)
cardano_seed: CardanoSeed = CardanoSeed(seed=seed, cardano_type=Cardano.TYPES.SHELLEY_LEDGER)

# Update Shelley-Ledger Cardano HD root keys from seed
cardano_hd.from_seed(
    seed=cardano_seed
)

# Dump root keys
print("Shelley-Ledger Seed:", cardano_seed.seed())
print("Shelley-Ledger Root XPrivate Key:", cardano_hd.root_xprivate_key())
print("Shelley-Ledger Root XPublic Key:", cardano_hd.root_xpublic_key())
print("Shelley-Ledger Root Chain Code:", cardano_hd.root_chain_code())
print("Shelley-Ledger Root Private Key:", cardano_hd.root_private_key())
print("Shelley-Ledger Root Public Key:", cardano_hd.root_public_key())

# Initialize CIP1852 derivation
cip1852_derivation: CIP1852Derivation = CIP1852Derivation(
    coin_type=Cardano.COIN_TYPE, role=ROLES.STAKING_KEY  # https://cips.cardano.org/cips/cip11
)
cip1852_derivation.from_account(account=0)
cip1852_derivation.from_address(address=0)

# Update current Shelley-Ledger Cardano HD derivation
cardano_hd.from_derivation(
    derivation=cip1852_derivation
)

# Dump derived staking keys
print("Staking Shelley-Ledger XPrivate Key:", cardano_hd.xprivate_key())
print("Staking Shelley-Ledger XPublic Key:", cardano_hd.xpublic_key())
print("Staking Shelley-Ledger Private Key:", cardano_hd.private_key())
print("Staking Shelley-Ledger Chain Code:", cardano_hd.chain_code())
staking_public_key: str = cardano_hd.public_key()
print("Staking Shelley-Ledger Public Key:", staking_public_key)
print("Staking Shelley-Ledger Depth:", cardano_hd.depth())
print("Staking Shelley-Ledger Path:", cardano_hd.path())
print("Staking Shelley-Ledger Index:", cardano_hd.index())
print("Staking Shelley-Ledger Indexes:", cardano_hd.indexes())
print("Staking Shelley-Ledger Fingerprint:", cardano_hd.fingerprint())
print("Staking Shelley-Ledger Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Staking Shelley-Ledger Address:", cardano_hd.address(address_type="staking"))

# Change CIP1852 Derivation role into external-chain
cip1852_derivation.from_role(
    role=ROLES.EXTERNAL_CHAIN
)

# Update current Shelley-Ledger Cardano HD derivation
cardano_hd.update_derivation(
    derivation=cip1852_derivation
)

# Dump derived keys
print("Shelley-Ledger XPrivate Key:", cardano_hd.xprivate_key())
print("Shelley-Ledger XPublic Key:", cardano_hd.xpublic_key())
print("Shelley-Ledger Private Key:", cardano_hd.private_key())
print("Shelley-Ledger Chain Code:", cardano_hd.chain_code())
print("Shelley-Ledger Public Key:", cardano_hd.public_key())
print("Shelley-Ledger Depth:", cardano_hd.depth())
print("Shelley-Ledger Path:", cardano_hd.path())
print("Shelley-Ledger Index:", cardano_hd.index())
print("Shelley-Ledger Indexes:", cardano_hd.indexes())
print("Shelley-Ledger Fingerprint:", cardano_hd.fingerprint())
print("Shelley-Ledger Parent Fingerprint:", cardano_hd.parent_fingerprint())
print("Shelley-Ledger Address:", cardano_hd.address(
    address_type="payment", staking_public_key=staking_public_key
))
