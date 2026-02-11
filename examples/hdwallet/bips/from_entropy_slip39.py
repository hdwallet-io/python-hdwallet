#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.entropies import (
    IEntropy, SLIP39Entropy, SLIP39_ENTROPY_STRENGTHS, BIP39Entropy, BIP39_ENTROPY_STRENGTHS,
)
from hdwallet.mnemonics import (
    IMnemonic, BIP39_MNEMONIC_LANGUAGES, BIP39Mnemonic, SLIP39Mnemonic
)
from hdwallet.seeds import (ISeed, SLIP39Seed)
from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.consts import PUBLIC_KEY_TYPES
from hdwallet.derivations import (
    BIP84Derivation, CHANGES
)
from hdwallet.hds import BIP84HD

import json

entropy_hex = "ffffffffffffffffffffffffffffffff"
entropy_bip39 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

slip39_entropy: IEntropy = SLIP39Entropy(
    entropy=entropy_hex
)
slip39_mnemonic: IMnemonic = SLIP39Mnemonic( SLIP39Mnemonic.from_entropy(
    entropy=slip39_entropy, language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
))
bip39_mnemonic: IMnemonic = BIP39Mnemonic( BIP39Mnemonic.from_entropy(
    entropy=entropy_hex, language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
))
assert bip39_mnemonic.mnemonic() == entropy_bip39

slip39_seed: ISeed = SLIP39Seed(
    seed=slip39_entropy.entropy()
)

slip39_seed_recovered = SLIP39Seed.from_mnemonic(slip39_mnemonic)
assert slip39_seed_recovered == slip39_seed.seed() == slip39_entropy.entropy()

#
# SLIP-39 can transport 128- or 256-bit entropy that is used DIRECTLY as an HD Wallet seed.
#
# This IS the standard way a Trezor SLIP-39 wallet recovery works, and produces the same wallets as
# if the Trezor hardware wallet was recovered using the SLIP-39 Mnemonics.
#
#    SLIP-39 Entropy:  ffffffffffffffffffffffffffffffff
# == 128-bit HD Wallet Seed
# 
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP84HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.ENGLISH,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase=""
).from_seed(
    seed=slip39_seed
)

assert hdwallet.address() == "bc1q9yscq3l2yfxlvnlk3cszpqefparrv7tk24u6pl"
assert hdwallet.entropy() == None
assert hdwallet.seed() == "ffffffffffffffffffffffffffffffff"


#
# A SLIP-39 encoded 128- or 256-bit entropy can also be converted into BIP-39 entropy, and then into
# BIP-39 Mnemonics.  This is NOT the normal Trezor SLIP-39 HD Wallet derivation; instead, it uses
# SLIP-39 to remember the original source entropy, and THEN encodes it into BIP-39 Mnemonics, and
# THEN uses mnemonics to recover the wallet via BIP-39 seed derivation.  However, this IS the best
# approach to backing up BIP-39 Mnemonics via SLIP-39, as it retains the BIP-39 passphrase, and
# results in exactly the same HD Wallet derivations as if the original BIP-39 Mnemonics had been
# entered directly.
#
#    SLIP-39 Entropy:  ffffffffffffffffffffffffffffffff
# => BIP-39 Mnemonic:  "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
# => BIP-39 Seed:      b6a6...25b6
# == 512-bit HD Wallet Seed
#
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP84HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.ENGLISH,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase=""
).from_entropy(
    entropy=slip39_entropy
)
assert hdwallet.address() == "bc1qk0a9hr7wjfxeenz9nwenw9flhq0tmsf6vsgnn2"
assert hdwallet.entropy() == "ffffffffffffffffffffffffffffffff"
assert hdwallet.seed() == "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6" \


# To "back up" an existing BIP-39 Mnemonic phrase into multiple SLIP-39 cards, there are 2 ways:
#
# 1) Back up the BIP-39 Mnemonic's *input* 128- or 256-bit entropy
#    a) decode the *input* entropy from the BIP-39 Mnemonic
#    b) generate 20- or 33-word SLIP-39 Mnemonic(s) encoding the *input* entropy
#      b1) optionally provide a SLIP-39 passphrase (not recommended)
#    (later)
#    c) recover the 128- or 256-bit entropy from 20- or 33-word SLIP-39 Mnemonic(s)
#      c1) enter the SLIP-39 passphrase (not recommended)
#    d) re-generate the BIP-39 Mnemonic from the entropy
#    e) recover the wallet from BIP-39 Mnemonic generated Seed
#      e1) enter the original BIP-39 passphrase
#
# 2) Back up the BIP-39 Mnemonic's *output* 512-bit seed
#    a) generate the 512-bit BIP-39 Seed from the Mnemonic
#      a1) enter the original BIP-39 passphrase
#    b) generate 59-word SLIP-39 Mnemonic(s) encoding the output seed
#      b1) optionally provide a SLIP-39 passphrase (not recommended)
#    (later)
#    c) recover the 512-bit seed from 59-word SLIP-39 Mnemonic(s)
#      c1) enter the SLIP-39 passphrase (not recommended)
#    d) recover the wallet from the 512-bit data as Seed
#      d1) no BIP-39 passphrase required

hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP84HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.ENGLISH,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase=""
).from_mnemonic(
    mnemonic=BIP39Mnemonic(mnemonic=entropy_bip39)
)
assert hdwallet.address() == "bc1qk0a9hr7wjfxeenz9nwenw9flhq0tmsf6vsgnn2"
assert hdwallet.entropy() == "ffffffffffffffffffffffffffffffff"
assert hdwallet.mnemonic() == entropy_bip39
assert hdwallet.seed() \
    == "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6"

# 1a-b) Decode and backup *input* entropy to SLIP-39 Mnemonics (size is 20 or 33 words based on input entropy size)
bip39_bu_1a_input_entropy = hdwallet.entropy()
bip39_bu_1b_input_slip39 = SLIP39Mnemonic.encode(
    entropy=bip39_bu_1a_input_entropy,
    language="Backup 4: One 1/1, Two 1/1, Fam 2/4, Fren 3/6",
    passphrase="Don't use this",  # 1b1) optional SLIP-39 passphrase - not well supported; leave empty
    tabulate=True,
)
#print(f"{bip39_bu_1b_input_slip39}")

# 1c-d) Recover *input* BIP-39 entropy from SLIP-39
bip39_bu_1c_input_entropy = SLIP39Mnemonic.decode(
    bip39_bu_1b_input_slip39,
    passphrase="Don't use this",  # 1c1) must match 1b1) - any passphrase is valid, produces different wallets
)
assert bip39_bu_1c_input_entropy == bip39_bu_1a_input_entropy

# 1e) Recover BIP-39 wallet from SLIP-39 entropy (converts to BIP-39 mnemonic)
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP84HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.ENGLISH,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase=""
).from_entropy(
    entropy=SLIP39Entropy(entropy=bip39_bu_1c_input_entropy)
)
assert hdwallet.address() == "bc1qk0a9hr7wjfxeenz9nwenw9flhq0tmsf6vsgnn2"
assert hdwallet.entropy() == "ffffffffffffffffffffffffffffffff"
assert hdwallet.mnemonic() == entropy_bip39
assert hdwallet.seed() \
    == "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6"

# 2a-b Recover *output* BIP-39 seed and backup to SLIP-39 Mnemonics (size is 59 based on 512-bit BIP-39 seed)
bip39_bu_2a_output_seed = hdwallet.seed()
bip39_bu_2b_output_slip39 = SLIP39Mnemonic.encode(
    entropy=bip39_bu_2a_output_seed,
    language="Backup 4: One 1/1, Two 1/1, Fam 2/4, Fren 3/6",
    passphrase="Don't use this",  # 2b1) optional SLIP-39 passphrase - not well supported; leave empty
    tabulate=True,
)
#print(f"{bip39_bu_2b_output_slip39}")

# 2c) Recover *output* BIP-39 seed from SLIP-39
bip39_bu_2c_output_seed = SLIP39Mnemonic.decode(
    bip39_bu_2b_output_slip39,
    passphrase="Don't use this",  # 2c1) must match 2b1) - any passphrase is valid, produces different wallets
)

# 2d) recover the wallet from the 512-bit data as Seed
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP84HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.ENGLISH,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase=""
).from_seed(
    seed=SLIP39Seed(seed=bip39_bu_2c_output_seed)
)
assert hdwallet.address() == "bc1qk0a9hr7wjfxeenz9nwenw9flhq0tmsf6vsgnn2"
assert hdwallet.entropy() == None
assert hdwallet.mnemonic() == None
assert hdwallet.seed() \
    == "b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6"


#print(json.dumps(hdwallet.dumps(exclude={"indexes"}), indent=4, ensure_ascii=False))

# print("Cryptocurrency:", hdwallet.cryptocurrency())
# print("Symbol:", hdwallet.symbol())
# print("Network:", hdwallet.network())
# print("Coin Type:", hdwallet.coin_type())
# print("Entropy:", hdwallet.entropy())
# print("Strength:", hdwallet.strength())
# print("Mnemonic:", hdwallet.mnemonic())
# print("Passphrase:", hdwallet.passphrase())
# print("Language:", hdwallet.language())
# print("Seed:", hdwallet.seed())
# print("ECC:", hdwallet.ecc())
# print("HD:", hdwallet.hd())
# print("Semantic:", hdwallet.semantic())
# print("Root XPrivate Key:", hdwallet.root_xprivate_key())
# print("Root XPublic Key:", hdwallet.root_xpublic_key())
# print("Root Private Key:", hdwallet.root_private_key())
# print("Root WIF:", hdwallet.root_wif())
# print("Root Chain Code:", hdwallet.root_chain_code())
# print("Root Public Key:", hdwallet.root_public_key())
# print("Strict:", hdwallet.strict())
# print("Public Key Type:", hdwallet.public_key_type())
# print("WIF Type:", hdwallet.wif_type())
# print("Path:", hdwallet.path())
# print("Depth:", hdwallet.depth())
# print("Indexes:", hdwallet.indexes())
# print("Index:", hdwallet.index())
# print("XPrivate Key:", hdwallet.xprivate_key())
# print("XPublic Key:", hdwallet.xpublic_key())
# print("Private Key:", hdwallet.private_key())
# print("WIF:", hdwallet.wif())
# print("Chain Code:", hdwallet.chain_code())
# print("Public Key:", hdwallet.public_key())
# print("Uncompressed:", hdwallet.uncompressed())
# print("Compressed:", hdwallet.compressed())
# print("Hash:", hdwallet.hash())
# print("Fingerprint:", hdwallet.fingerprint())
# print("Parent Fingerprint:", hdwallet.parent_fingerprint())
# print("Address:", hdwallet.address())
