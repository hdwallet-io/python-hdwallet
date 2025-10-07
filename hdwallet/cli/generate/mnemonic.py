#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import click
import sys

from ...mnemonics import (
    IMnemonic,
    AlgorandMnemonic, ALGORAND_MNEMONIC_WORDS, ALGORAND_MNEMONIC_LANGUAGES,
    BIP39Mnemonic, BIP39_MNEMONIC_WORDS, BIP39_MNEMONIC_LANGUAGES,
    SLIP39Mnemonic, SLIP39_MNEMONIC_WORDS, SLIP39_MNEMONIC_LANGUAGES,
    ElectrumV1Mnemonic, ELECTRUM_V1_MNEMONIC_WORDS, ELECTRUM_V1_MNEMONIC_LANGUAGES,
    ElectrumV2Mnemonic, ELECTRUM_V2_MNEMONIC_WORDS, ELECTRUM_V2_MNEMONIC_LANGUAGES,
    MoneroMnemonic, MONERO_MNEMONIC_WORDS, MONERO_MNEMONIC_LANGUAGES,
    MNEMONICS
)


def generate_mnemonic(**kwargs) -> None:
    """Produce a Mnemonic of type 'client' in 'language'.  Source from 'entropy' or 'mnemonic', or
    produce new entropy appropriate for a certain number of mnemonic 'words'.

    """
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
            elif kwargs.get("client") == SLIP39Mnemonic.name():
                language: str = SLIP39_MNEMONIC_LANGUAGES.ENGLISH
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
            elif kwargs.get("client") == SLIP39Mnemonic.name():
                words: int = SLIP39_MNEMONIC_WORDS.TWENTY
            elif kwargs.get("client") == ElectrumV1Mnemonic.name():
                words: int = ELECTRUM_V1_MNEMONIC_WORDS.TWELVE
            elif kwargs.get("client") == ElectrumV2Mnemonic.name():
                words: int = ELECTRUM_V2_MNEMONIC_WORDS.TWELVE
            elif kwargs.get("client") == MoneroMnemonic.name():
                words: int = MONERO_MNEMONIC_WORDS.TWELVE
        else:
            words: int = kwargs.get("words")

        if not MNEMONICS.mnemonic(name=kwargs.get("client")).is_valid_language(language):
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

        if kwargs.get("entropy") and kwargs.get("mnemonic"):
            click.echo(click.style(
                "Supply either --entropy or --mnemonic, not both"
            ), err=True)
            sys.exit()

        if kwargs.get("mnemonic"):
            # Get source entropy from another mnemonic.  Doesn't support those requiring another
            # different 'mnemonic_type' from that supplied for the output mnemonic.  Recovering the
            # original entropy from certain Mnemonics such as SLIP39 requires an optional
            # passphrase.  For most Mnemonic clients, a passphrase doesn't hide the original entropy
            # -- it is used only when deriving wallets.
            if not MNEMONICS.is_mnemonic(name=kwargs.get("mnemonic_client")):
                click.echo(click.style(
                    f"Wrong mnemonic client, (expected={MNEMONICS.names()}, got='{kwargs.get('mnemonic_client')}')"
                ), err=True)
                sys.exit()
            if kwargs.get("mnemonic_client") == ElectrumV2Mnemonic.name():
                entropy: str = ElectrumV2Mnemonic.decode(
                    mnemonic=kwargs.get("mnemonic"),
                    language=kwargs.get("language"),
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            elif kwargs.get("mnemonic_client") == SLIP39Mnemonic.name():
                entropy: str = SLIP39Mnemonic.decode(
                    mnemonic=kwargs.get("mnemonic"),
                    language=kwargs.get("language"),
                    passphrase=kwargs.get("mnemonic_passphrase") or "",
                )
            else:
                entropy: str = MNEMONICS.mnemonic(name=kwargs.get("mnemonic_client")).decode(
                    mnemonic=kwargs.get("mnemonic"),
                    language=kwargs.get("language"),
                )
            # Now, use the recovered 'entropy' in deriving the new 'client' mnemonic.
            kwargs["entropy"] = entropy

        if kwargs.get("entropy"):
            if kwargs.get("client") == ElectrumV2Mnemonic.name():
                mnemonic: IMnemonic = ElectrumV2Mnemonic(
                    mnemonic=ElectrumV2Mnemonic.from_entropy(
                        entropy=kwargs.get("entropy"),
                        language=language,
                        mnemonic_type=kwargs.get("mnemonic_type"),
                        max_attempts=kwargs.get("max_attempts")
                    ),
                    language=language,
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            elif kwargs.get("client") == MoneroMnemonic.name():
                mnemonic: IMnemonic = MoneroMnemonic(
                    mnemonic=MoneroMnemonic.from_entropy(
                        entropy=kwargs.get("entropy"),
                        language=language,
                        checksum=kwargs.get("checksum")
                    ),
                    language=language,
                )
            elif kwargs.get("client") == SLIP39Mnemonic.name():
                # The supplied 'entropy', encoded w/ the SLIP-39 'language', and encrypted w/
                # 'passphrase' (default: "").  We remember the supplied language, because it
                # deterministically describes the SLIP-39 secret and group encoding parameters, and
                # can also contain specifics like the SLIP-39's overall name and groups' names.  Any
                # 'tabulate' supplied influences the formatting of the groups of SLIP-39 Mnemonics.
                mnemonic: IMnemonic = SLIP39Mnemonic(
                    mnemonic=SLIP39Mnemonic.from_entropy(
                        entropy=kwargs.get("entropy"),
                        language=language,
                        passphrase=kwargs.get("passphrase") or "",
                    ),
                    language=language,
                    tabulate=kwargs.get("tabulate", False),
                )
            else:
                mnemonic: IMnemonic = MNEMONICS.mnemonic(name=kwargs.get("client")).__call__(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("client")).from_entropy(
                        entropy=kwargs.get("entropy"), language=language
                    ),
                    language=language,
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
                    language=language,
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            else:
                mnemonic: IMnemonic = MNEMONICS.mnemonic(name=kwargs.get("client")).__call__(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("client")).from_words(
                        words=words, language=language
                    ),
                    language=language,
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
