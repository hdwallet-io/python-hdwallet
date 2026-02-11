#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.mnemonics.electrum.v1.mnemonic import (
    ElectrumV1Mnemonic, ELECTRUM_V1_MNEMONIC_LANGUAGES, ELECTRUM_V1_MNEMONIC_WORDS
)
from hdwallet.exceptions import (
    MnemonicError, EntropyError
)


def test_electrum_v1_mnemonics(data):
    
    assert ELECTRUM_V1_MNEMONIC_WORDS.TWELVE == 12
    assert ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH == "english"


    for __ in data["mnemonics"]["Electrum-V1"]:
        assert ElectrumV1Mnemonic.is_valid_words(words=__["words"])

        for language in __["languages"].keys():

            assert ElectrumV1Mnemonic.is_valid_language(language=language)
            assert ElectrumV1Mnemonic.is_valid(mnemonic=__["languages"][language])

            mnemonic = ElectrumV1Mnemonic.from_words(words=__["words"], language=language)
            assert len(mnemonic.split()) == __["words"]
            assert ElectrumV1Mnemonic(mnemonic=mnemonic).language().lower() == language

            assert ElectrumV1Mnemonic.from_entropy(entropy=__["entropy"], language=language) == __["languages"][language]
            assert ElectrumV1Mnemonic.decode(mnemonic=__["languages"][language]) == __["entropy"]

            mnemonic = ElectrumV1Mnemonic(mnemonic=__["languages"][language], language=language)

            assert mnemonic.name() == __["name"]
            assert mnemonic.language().lower() == language

    with pytest.raises(Exception, match="Invalid Electrum-V1 mnemonic words"): 
        ElectrumV1Mnemonic(
            mnemonic="flower letter world foil coin poverty romance tongue taste hip cradle follow proud pluck ten improve",
        )

    with pytest.raises(MnemonicError, match="Invalid mnemonic words number"):
        ElectrumV1Mnemonic.from_words(
            words=100, language=ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Invalid entropy instance"):
        ElectrumV1Mnemonic.from_entropy(
            entropy={"FAKE_ENTROPY_DICT"}, language=ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Wrong entropy strength"):
        ElectrumV1Mnemonic.from_entropy(
            entropy="cdf694ac868efd01673fc51e897c57a0bd428503080ad4c94c7d6f6d13f095fbc8",
            language=ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH
        )
