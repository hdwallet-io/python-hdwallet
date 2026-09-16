#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.mnemonics.bip39.mnemonic import (
    BIP39Mnemonic, BIP39_MNEMONIC_LANGUAGES, BIP39_MNEMONIC_WORDS
)
from hdwallet.exceptions import (
    MnemonicError, EntropyError
)


def test_bip39_mnemonics(data):
    
    assert BIP39_MNEMONIC_WORDS.TWELVE == 12
    assert BIP39_MNEMONIC_WORDS.FIFTEEN == 15
    assert BIP39_MNEMONIC_WORDS.EIGHTEEN == 18
    assert BIP39_MNEMONIC_WORDS.TWENTY_ONE == 21
    assert BIP39_MNEMONIC_WORDS.TWENTY_FOUR == 24


    assert BIP39_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED == "chinese-simplified"
    assert BIP39_MNEMONIC_LANGUAGES.CHINESE_TRADITIONAL == "chinese-traditional"
    assert BIP39_MNEMONIC_LANGUAGES.CZECH == "czech"
    assert BIP39_MNEMONIC_LANGUAGES.ENGLISH == "english"
    assert BIP39_MNEMONIC_LANGUAGES.FRENCH == "french"
    assert BIP39_MNEMONIC_LANGUAGES.ITALIAN == "italian"
    assert BIP39_MNEMONIC_LANGUAGES.JAPANESE == "japanese"
    assert BIP39_MNEMONIC_LANGUAGES.KOREAN == "korean"
    assert BIP39_MNEMONIC_LANGUAGES.PORTUGUESE == "portuguese"
    assert BIP39_MNEMONIC_LANGUAGES.RUSSIAN == "russian"
    assert BIP39_MNEMONIC_LANGUAGES.SPANISH == "spanish"
    assert BIP39_MNEMONIC_LANGUAGES.TURKISH == "turkish"

    for __ in data["mnemonics"]["BIP39"]:
        assert BIP39Mnemonic.is_valid_words(words=__["words"])

        for language in __["languages"].keys():

            assert BIP39Mnemonic.is_valid_language(language=language)
            assert BIP39Mnemonic.is_valid(mnemonic=__["languages"][language])

            mnemonic = BIP39Mnemonic.from_words(words=__["words"], language=language)
            assert len(mnemonic.split()) == __["words"]
            assert BIP39Mnemonic(mnemonic=mnemonic).language().lower() == language

            assert BIP39Mnemonic.from_entropy(entropy=__["entropy"], language=language) == __["languages"][language]
            assert BIP39Mnemonic.decode(mnemonic=__["languages"][language]) == __["entropy"]

            mnemonic = BIP39Mnemonic(mnemonic=__["languages"][language])

            assert mnemonic.name() == __["name"]
            assert mnemonic.language().lower() == language

    with pytest.raises(Exception, match="Invalid mnemonic words"): 
        BIP39Mnemonic(
            mnemonic="judge pigeon dove nerve blood fossil wet suggest this level bottom journey tornado "
                     "hurt ritual hobby label alpha fruit ensure unit animal mouse absorb ramp"
        )

    with pytest.raises(MnemonicError, match="Invalid mnemonic words number"):
        BIP39Mnemonic.from_words(
            words=100, language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Invalid entropy instance"):
        BIP39Mnemonic.from_entropy(
            entropy={"FAKE_ENTROPY_DICT"}, language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Wrong entropy strength"):
        BIP39Mnemonic.from_entropy(
            entropy="cdf694ac868efd01673fc51e897c57a0bd428503080ad4c94c7d6f6d13f095fbc8",
            language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
        )
