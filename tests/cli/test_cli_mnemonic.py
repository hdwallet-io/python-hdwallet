#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import unicodedata

from hdwallet.cli.__main__ import cli_main
from hdwallet.mnemonics.imnemonic import unmark

def check_mnemonics(
    cli_word,
    cli_entropy,
    client,
    language, 
    words, 
    entropy,
    mnemonic
):
    def nfc_unmarked_set( phrase ):
        nfc = unicodedata.normalize( "NFC", phrase )
        return set( (nfc, unmark( nfc )) )

    def json_parser( json_i ):
        json_s = ''.join( json_i )
        try:
            data = json.loads(json_s)
        except Exception as exc:
            print( f"Failed to parse JSON: {exc} from:\n{json_s}" )
            raise
        return data

    try:

        output_word = json_parser( cli_word.output )
        output_entropy = json_parser( cli_entropy.output )
        
        assert cli_word.exit_code == 0
        assert cli_entropy.exit_code == 0
    
        assert output_word["client"] == client
        assert output_entropy["client"] == client
    
        assert output_word["words"] == words
        assert output_entropy["words"] == words
    
        assert output_word["language"].lower() == language
        assert output_entropy["language"].lower() == language
    
        # Mnemonics recovered will be in NFC form, and my be with or without Unicode Marks (for
        # example, mnemonics that are ambiguous between English and French may not have accents).
        assert nfc_unmarked_set( mnemonic ) & nfc_unmarked_set( output_entropy["mnemonic"] )

    except Exception as exc:
        print( f"Failed {client} w/ {language} mnemonic: {mnemonic}: {exc}" )
        raise

def test_cli_mnemonic(data, cli_tester):

    for client in data["mnemonics"].keys():
        for mnemonic_data in data["mnemonics"][client]:
            if client == "Electrum-V2":
                for mnemonic_type in mnemonic_data["mnemonic-types"].keys():
                    for language in mnemonic_data["mnemonic-types"][mnemonic_type].keys():
                        cli_word = cli_tester.invoke(
                            cli_main, [
                                "generate", "mnemonic",
                                "--client", client,
                                "--mnemonic-type", mnemonic_type,
                                "--words", mnemonic_data["words"],
                                "--language", language
                            ]
                        )

                        cli_entropy = cli_tester.invoke(
                            cli_main, [
                                "generate", "mnemonic",
                                "--client", client,
                                "--mnemonic-type", mnemonic_type,
                                "--entropy", mnemonic_data["entropy-not-suitable"],
                                "--language", language
                            ]
                        )

                        check_mnemonics(
                            cli_word=cli_word,
                            cli_entropy=cli_entropy,
                            client=client,
                            language=language,
                            words=mnemonic_data["words"],
                            entropy=mnemonic_data["entropy-not-suitable"],
                            mnemonic=mnemonic_data["mnemonic-types"][mnemonic_type][language]["mnemonic"]
                        )
            else:
                for language in mnemonic_data["languages"].keys():
                    cli_word = cli_tester.invoke(
                        cli_main, [
                            "generate", "mnemonic",
                            "--client", client,
                            "--words", mnemonic_data["words"],
                            "--language", language
                        ]
                    )

                    entropy_args = [
                            "generate", "mnemonic",
                            "--client", client,
                            "--entropy", mnemonic_data["entropy"],
                            "--language", language
                        ]

                    if client == "Monero":
                        entropy_args.append("--checksum")
                        entropy_args.append(str(mnemonic_data["checksum"]))

                    #print(" ".join(entropy_args))
                    cli_entropy = cli_tester.invoke(
                        cli_main, entropy_args
                    )
                    #print(f" --> {cli_entropy.output}")

                    check_mnemonics(
                        cli_word=cli_word,
                        cli_entropy=cli_entropy,
                        client=client,
                        language=language,
                        words=mnemonic_data["words"],
                        entropy=mnemonic_data["entropy"],
                        mnemonic=mnemonic_data["languages"][language]
                    )

