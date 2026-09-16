#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.mnemonics.algorand.mnemonic import (
    AlgorandMnemonic, ALGORAND_MNEMONIC_LANGUAGES, ALGORAND_MNEMONIC_WORDS
)
from hdwallet.exceptions import (
    MnemonicError, EntropyError
)


def test_algorand_mnemonics(data):
    
    assert ALGORAND_MNEMONIC_WORDS.TWENTY_FIVE == 25
    assert ALGORAND_MNEMONIC_LANGUAGES.ENGLISH == "english"


    for __ in data["mnemonics"]["Algorand"]:
        assert AlgorandMnemonic.is_valid_words(words=__["words"])

        for language in __["languages"].keys():

            assert AlgorandMnemonic.is_valid_language(language=language)
            assert AlgorandMnemonic.is_valid(mnemonic=__["languages"][language])

            mnemonic = AlgorandMnemonic.from_words(words=__["words"], language=language)
            assert len(mnemonic.split()) == __["words"]
            assert AlgorandMnemonic(mnemonic=mnemonic).language().lower() == language

            assert AlgorandMnemonic.from_entropy(entropy=__["entropy"], language=language) == __["languages"][language]
            assert AlgorandMnemonic.decode(mnemonic=__["languages"][language]) == __["entropy"]

            mnemonic = AlgorandMnemonic(mnemonic=__["languages"][language])

            assert mnemonic.name() == __["name"]
            assert mnemonic.language().lower() == language

    with pytest.raises(MnemonicError, match="Invalid mnemonic words"): 
        AlgorandMnemonic(
            mnemonic="flower letter world foil coin poverty romance tongue taste hip cradle follow proud pluck ten improve"
        )

    with pytest.raises(MnemonicError, match="Invalid mnemonic words number"):
        AlgorandMnemonic.from_words(
            words=100, language=ALGORAND_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Invalid entropy instance"):
        AlgorandMnemonic.from_entropy(
            entropy={"FAKE_ENTROPY_DICT"}, language=ALGORAND_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Wrong entropy strength"):
        AlgorandMnemonic.from_entropy(
            entropy="cdf694ac868efd01673fc51e897c57a0bd428503080ad4c94c7d6f6d13f095fbc8",
            language=ALGORAND_MNEMONIC_LANGUAGES.ENGLISH
        )
