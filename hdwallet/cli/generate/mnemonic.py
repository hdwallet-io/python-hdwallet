#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import click
import sys

from ...mnemonics import (
    IMnemonic,
    AlgorandMnemonic, ALGORAND_MNEMONIC_WORDS, ALGORAND_MNEMONIC_LANGUAGES,
    BIP39Mnemonic, BIP39_MNEMONIC_WORDS, BIP39_MNEMONIC_LANGUAGES,
    ElectrumV1Mnemonic, ELECTRUM_V1_MNEMONIC_WORDS, ELECTRUM_V1_MNEMONIC_LANGUAGES,
    ElectrumV2Mnemonic, ELECTRUM_V2_MNEMONIC_WORDS, ELECTRUM_V2_MNEMONIC_LANGUAGES,
    MoneroMnemonic, MONERO_MNEMONIC_WORDS, MONERO_MNEMONIC_LANGUAGES,
    MNEMONICS
)


def generate_mnemonic(**kwargs) -> None:
    try:
        if not MNEMONICS.is_mnemonic(name=kwargs.get("client")):
            click.echo(click.style(
                f"Wrong mnemonic client, (expected={MNEMONICS.names()}, got='{kwargs.get('client')}')"
            ), err=True)
            sys.exit()

        if kwargs.get("language") is None:  # Set default language
            if kwargs.get("client") == AlgorandMnemonic.name():
                language: str = ALGORAND_MNEMONIC_LANGUAGES.ENGLISH
            elif kwargs.get("client") == BIP39Mnemonic.name():
                language: str = BIP39_MNEMONIC_LANGUAGES.ENGLISH
            elif kwargs.get("client") == ElectrumV1Mnemonic.name():
                language: str = ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH
            elif kwargs.get("client") == ElectrumV2Mnemonic.name():
                language: str = ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH
            elif kwargs.get("client") == MoneroMnemonic.name():
                language: str = MONERO_MNEMONIC_LANGUAGES.ENGLISH
        else:
            language: str = kwargs.get("language")

        if kwargs.get("words") is None:  # Set default words
            if kwargs.get("client") == AlgorandMnemonic.name():
                words: int = ALGORAND_MNEMONIC_WORDS.TWENTY_FIVE
            elif kwargs.get("client") == BIP39Mnemonic.name():
                words: int = BIP39_MNEMONIC_WORDS.TWELVE
            elif kwargs.get("client") == ElectrumV1Mnemonic.name():
                words: int = ELECTRUM_V1_MNEMONIC_WORDS.TWELVE
            elif kwargs.get("client") == ElectrumV2Mnemonic.name():
                words: int = ELECTRUM_V2_MNEMONIC_WORDS.TWELVE
            elif kwargs.get("client") == MoneroMnemonic.name():
                words: int = MONERO_MNEMONIC_WORDS.TWELVE
        else:
            words: int = kwargs.get("words")

        if not MNEMONICS.mnemonic(name=kwargs.get("client")).is_valid_language(language=language):
            click.echo(click.style(
                f"Wrong {kwargs.get('client')} mnemonic language, "
                f"(expected={MNEMONICS.mnemonic(name=kwargs.get('client')).languages}, got='{language}')"
            ), err=True)
            sys.exit()

        if not MNEMONICS.mnemonic(name=kwargs.get("client")).is_valid_words(words=words):
            click.echo(click.style(
                f"Wrong {kwargs.get('client')} mnemonic words, "
                f"(expected={MNEMONICS.mnemonic(name=kwargs.get('client')).words}, got='{words}')"
            ), err=True)
            sys.exit()

        if kwargs.get("entropy"):
            if kwargs.get("client") == ElectrumV2Mnemonic.name():
                mnemonic: IMnemonic = ElectrumV2Mnemonic(
                    mnemonic=ElectrumV2Mnemonic.from_entropy(
                        entropy=kwargs.get("entropy"),
                        language=language,
                        mnemonic_type=kwargs.get("mnemonic_type"),
                        max_attempts=kwargs.get("max_attempts")
                    ),
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            elif kwargs.get("client") == MoneroMnemonic.name():
                mnemonic: IMnemonic = MoneroMnemonic(
                    mnemonic=MoneroMnemonic.from_entropy(
                        entropy=kwargs.get("entropy"),
                        language=language,
                        checksum=kwargs.get("checksum")
                    )
                )
            else:
                mnemonic: IMnemonic = MNEMONICS.mnemonic(name=kwargs.get("client")).__call__(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("client")).from_entropy(
                        entropy=kwargs.get("entropy"), language=language
                    )
                )
        else:
            if kwargs.get("client") == ElectrumV2Mnemonic.name():
                mnemonic: IMnemonic = ElectrumV2Mnemonic(
                    mnemonic=ElectrumV2Mnemonic.from_words(
                        words=words,
                        language=language,
                        mnemonic_type=kwargs.get("mnemonic_type"),
                        max_attempts=kwargs.get("max_attempts")
                    ),
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            else:
                mnemonic: IMnemonic = MNEMONICS.mnemonic(name=kwargs.get("client")).__call__(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("client")).from_words(
                        words=words, language=language
                    )
                )
        output: dict = {
            "client": mnemonic.name(),
            "mnemonic": mnemonic.mnemonic(),
            "language": mnemonic.language(),
            "words": mnemonic.words()
        }
        if mnemonic.name() == ElectrumV2Mnemonic.name():
            output["mnemonic_type"] = kwargs.get("mnemonic_type")
        click.echo(json.dumps(
            output, indent=kwargs.get("indent", 4), ensure_ascii=kwargs.get("ensure_ascii", False)
        ))

    except Exception as exception:
        click.echo(click.style(f"Error: {str(exception)}"), err=True)
        sys.exit()
