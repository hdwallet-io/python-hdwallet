#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest
import unicodedata

from hdwallet.mnemonics.monero.mnemonic import (
    MoneroMnemonic, MONERO_MNEMONIC_LANGUAGES, MONERO_MNEMONIC_WORDS
)
from hdwallet.exceptions import (
    MnemonicError, EntropyError
)


def test_monero_mnemonics(data):
    
    assert MONERO_MNEMONIC_WORDS.TWELVE == 12
    assert MONERO_MNEMONIC_WORDS.THIRTEEN == 13
    assert MONERO_MNEMONIC_WORDS.TWENTY_FOUR == 24
    assert MONERO_MNEMONIC_WORDS.TWENTY_FIVE == 25

    assert MONERO_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED == "chinese-simplified"
    assert MONERO_MNEMONIC_LANGUAGES.DUTCH == "dutch"
    assert MONERO_MNEMONIC_LANGUAGES.ENGLISH == "english"
    assert MONERO_MNEMONIC_LANGUAGES.FRENCH == "french"
    assert MONERO_MNEMONIC_LANGUAGES.GERMAN == "german"
    assert MONERO_MNEMONIC_LANGUAGES.ITALIAN == "italian"
    assert MONERO_MNEMONIC_LANGUAGES.JAPANESE == "japanese"
    assert MONERO_MNEMONIC_LANGUAGES.PORTUGUESE == "portuguese"
    assert MONERO_MNEMONIC_LANGUAGES.RUSSIAN == "russian"
    assert MONERO_MNEMONIC_LANGUAGES.SPANISH == "spanish"

    for __ in data["mnemonics"]["Monero"]:
        assert MoneroMnemonic.is_valid_words(words=__["words"])

        for language in __["languages"].keys():
            assert MoneroMnemonic.is_valid(mnemonic=__["languages"][language], language=language)

            mnemonic = MoneroMnemonic.from_words(words=__["words"], language=language)
            assert len(mnemonic.split()) == __["words"]
            assert MoneroMnemonic(mnemonic=mnemonic, language=language).language().lower() == language

            assert MoneroMnemonic.from_entropy(entropy=__["entropy"], checksum=__["checksum"], language=language) == unicodedata.normalize("NFC", __["languages"][language])
            assert MoneroMnemonic.decode(mnemonic=__["languages"][language], language=language) == __["entropy"]

            mnemonic = MoneroMnemonic(mnemonic=__["languages"][language], language=language)

            assert mnemonic.name() == __["name"]
            assert mnemonic.language().lower() == language

    with pytest.raises(MnemonicError, match="Invalid Monero mnemonic words"): 
        MoneroMnemonic(
            mnemonic="flower letter world foil coin poverty romance tongue taste hip cradle follow proud pluck ten improve"
        )

    with pytest.raises(MnemonicError, match="Invalid mnemonic words number"):
        MoneroMnemonic.from_words(
            words=100, language=MONERO_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Invalid entropy instance"):
        MoneroMnemonic.from_entropy(
            entropy={"FAKE_ENTROPY_DICT"}, language=MONERO_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Wrong entropy strength"):
        MoneroMnemonic.from_entropy(
            entropy="cdf694ac868efd01673fc51e897c57a0bd428503080ad4c94c7d6f6d13f095fbc8",
            language=MONERO_MNEMONIC_LANGUAGES.ENGLISH
        )
