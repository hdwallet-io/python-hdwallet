#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest
import unicodedata

from hdwallet.mnemonics.electrum.v2.mnemonic import (
    ElectrumV2Mnemonic, ELECTRUM_V2_MNEMONIC_LANGUAGES, ELECTRUM_V2_MNEMONIC_WORDS
)
from hdwallet.exceptions import (
    Error, MnemonicError, EntropyError
)


def test_electrum_v2_mnemonics(data):
    
    assert ELECTRUM_V2_MNEMONIC_WORDS.TWELVE == 12
    assert ELECTRUM_V2_MNEMONIC_WORDS.TWENTY_FOUR == 24

    assert ELECTRUM_V2_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED == "chinese-simplified"
    assert ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH == "english"
    assert ELECTRUM_V2_MNEMONIC_LANGUAGES.PORTUGUESE == "portuguese"
    assert ELECTRUM_V2_MNEMONIC_LANGUAGES.SPANISH == "spanish"


    for __ in data["mnemonics"]["Electrum-V2"]:
        assert ElectrumV2Mnemonic.is_valid_words(words=__["words"])

        for mnemonic_type in __["mnemonic-types"].keys():
            for language in __["mnemonic-types"][mnemonic_type].keys():
                assert ElectrumV2Mnemonic.is_valid_language(language=language)
                mnemonic_words=__["mnemonic-types"][mnemonic_type][language]["mnemonic"]

                assert ElectrumV2Mnemonic.is_valid(
                    mnemonic=mnemonic_words, language=language, mnemonic_type=mnemonic_type
                )

                mnemonic = ElectrumV2Mnemonic.from_words(words=__["words"], language=language, mnemonic_type=mnemonic_type)
                assert len(mnemonic.split()) == __["words"]
                assert ElectrumV2Mnemonic(mnemonic=mnemonic, language=language, mnemonic_type=mnemonic_type).language().lower() == language

                assert ElectrumV2Mnemonic.from_entropy(
                    entropy=__["entropy-not-suitable"], mnemonic_type=mnemonic_type, language=language
                ) == unicodedata.normalize("NFC", __["mnemonic-types"][mnemonic_type][language]["mnemonic"])

                assert ElectrumV2Mnemonic.decode(
                    mnemonic=__["mnemonic-types"][mnemonic_type][language]["mnemonic"], language=language, mnemonic_type=mnemonic_type
                ) == __["mnemonic-types"][mnemonic_type][language]["entropy-suitable"]

                mnemonic = ElectrumV2Mnemonic(
                    mnemonic=__["mnemonic-types"][mnemonic_type][language]["mnemonic"], language=language, mnemonic_type=mnemonic_type
                )
                assert mnemonic.name() == __["name"]
                assert mnemonic.language().lower() == language
                assert mnemonic.mnemonic_type() == mnemonic_type
                

    with pytest.raises(Exception, match="Invalid mnemonic words"): 
        ElectrumV2Mnemonic(
            mnemonic="flower letter world foil coin poverty romance tongue taste hip cradle follow proud pluck ten improve"
        )

    with pytest.raises(MnemonicError, match="Invalid mnemonic words number"):
        ElectrumV2Mnemonic.from_words(
            words=100, language=ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(EntropyError, match="Invalid entropy instance"):
        ElectrumV2Mnemonic.from_entropy(
            entropy={"FAKE_ENTROPY_DICT"}, language=ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH
        )

    with pytest.raises(Error, match="Unable to generate a valid mnemonic"):
        ElectrumV2Mnemonic.from_entropy(
            entropy="7c2abbf52d1861b978792df3dc88e7e27dbe36c7a0287893",
            language=ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH
        )
