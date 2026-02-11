#!/usr/bin/env python3

from typing import Type

from hdwallet.mnemonics import (
    MNEMONICS, IMnemonic, SLIP39Mnemonic, SLIP39_MNEMONIC_LANGUAGES, SLIP39_MNEMONIC_WORDS
)

data = {
    "name": "SLIP39",
    "entropy": "b66022fff8b6322f8b8fa444d6d097457b6b9e7bb05add5b75f9c827df7bd3b6",
    "mnemonic": (
        "drug cleanup academic academic august branch cage company example duke"
        " uncover glen already mortgage ticket emphasis papa agree fitness capacity"
        " evening glad trust raspy year sweater hormone database kernel cultural"
        " fact angry goat"
    ),
    "language": SLIP39_MNEMONIC_LANGUAGES.ENGLISH,
    "words": SLIP39_MNEMONIC_WORDS.THIRTY_THREE,
}

SLIP39MnemonicClass: Type[IMnemonic] = MNEMONICS.mnemonic(data["name"])

slip39_mnemonic_class = SLIP39MnemonicClass(data["mnemonic"])
slip39_mnemonic = SLIP39Mnemonic(data["mnemonic"])

print(
    slip39_mnemonic_class.decode(mnemonic=slip39_mnemonic_class.mnemonic())
    == slip39_mnemonic.decode(mnemonic=slip39_mnemonic.mnemonic())
    == slip39_mnemonic_class.decode(SLIP39MnemonicClass.from_entropy(data["entropy"], data["language"]))
    == slip39_mnemonic.decode(SLIP39Mnemonic.from_entropy(data["entropy"], data["language"]))
    == SLIP39Mnemonic.decode(mnemonic=data["mnemonic"]),

    slip39_mnemonic_class.language() == slip39_mnemonic.language() == data["language"],

    slip39_mnemonic_class.words() == slip39_mnemonic.words() == data["words"],

    SLIP39MnemonicClass.is_valid(data["mnemonic"]) == SLIP39Mnemonic.is_valid(data["mnemonic"]),

    SLIP39MnemonicClass.is_valid_language(data["language"]) == SLIP39Mnemonic.is_valid_language(data["language"]),

    SLIP39MnemonicClass.is_valid_words(data["words"]) == SLIP39Mnemonic.is_valid_words(data["words"]),

    len(SLIP39MnemonicClass.from_words(data["words"], data["language"]).split(" ")) ==
    len(SLIP39Mnemonic.from_words(data["words"], data["language"]).split(" ")), "\n"
)

print("Client:", data["name"])
print("Mnemonic:", data["mnemonic"])
print("Language:", data["language"])
print("Words:", data["words"])
