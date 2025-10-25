#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import click
import sys

from ...mnemonics import MNEMONICS
from ...seeds import (
    ISeed, BIP39Seed, SLIP39Seed, CardanoSeed, ElectrumV2Seed, SEEDS
)


def generate_seed(**kwargs) -> None:
    try:
        if not kwargs.get("mnemonic"):
            click.echo(click.style(f"Mnemonic is required for {kwargs.get('client')} client"), err=True)
            sys.exit()

        if not SEEDS.is_seed(name=kwargs.get("client")):
            click.echo(click.style(
                f"Wrong seed client, (expected={SEEDS.names()}, got='{kwargs.get('client')}')"
            ), err=True)
            sys.exit()

        if kwargs.get("client") == ElectrumV2Seed.name():
            if not MNEMONICS.mnemonic(name="Electrum-V2").is_valid(
                mnemonic=kwargs.get("mnemonic"), mnemonic_type=kwargs.get("mnemonic_type")
            ):
                click.echo(click.style("Invalid Electrum-V2 mnemonic"), err=True)
                sys.exit()
        elif kwargs.get("client") != SLIP39Seed.name():  # SLIP39 supports any 128-, 256- or 512-bit Mnemonic
            mnemonic_name: str = "BIP39" if kwargs.get("client") == CardanoSeed.name() else kwargs.get("client")
            if not MNEMONICS.mnemonic(name=mnemonic_name).is_valid(mnemonic=kwargs.get("mnemonic"), language=kwargs.get("language")):
                click.echo(click.style(f"Invalid {mnemonic_name} mnemonic"), err=True)
                sys.exit()

        if kwargs.get("client") == BIP39Seed.name():
            seed: ISeed = BIP39Seed(
                seed=BIP39Seed.from_mnemonic(
                    mnemonic=kwargs.get("mnemonic"),
                    passphrase=kwargs.get("passphrase"),
                    language=kwargs.get("language"),
                )
            )
        elif kwargs.get("client") == SLIP39Seed.name():
            seed: ISeed = SLIP39Seed(
                seed=SLIP39Seed.from_mnemonic(
                    mnemonic=kwargs.get("mnemonic"),
                    passphrase=kwargs.get("passphrase"),
                    language=kwargs.get("language"),
                )
            )
        elif kwargs.get("client") == CardanoSeed.name():
            seed: ISeed = CardanoSeed(
                seed=CardanoSeed.from_mnemonic(
                    mnemonic=kwargs.get("mnemonic"),
                    passphrase=kwargs.get("passphrase"),
                    language=kwargs.get("language"),
                    cardano_type=kwargs.get("cardano_type")
                )
            )
        elif kwargs.get("client") == ElectrumV2Seed.name():
            seed: ISeed = ElectrumV2Seed(
                seed=ElectrumV2Seed.from_mnemonic(
                    mnemonic=kwargs.get("mnemonic"),
                    passphrase=kwargs.get("passphrase"),
                    language=kwargs.get("language"),
                    mnemonic_type=kwargs.get("mnemonic_type")
                )
            )
        else:
            seed: ISeed = SEEDS.seed(name=kwargs.get("client")).__call__(
                seed=SEEDS.seed(name=kwargs.get("client")).from_mnemonic(
                    mnemonic=kwargs.get("mnemonic"),
                    language=kwargs.get("language"),
                )
            )
        output: dict = {
            "client": seed.name(),
            "seed": seed.seed()
        }
        if seed.name() == CardanoSeed.name():
            output["cardano_type"] = kwargs.get("cardano_type")
        elif seed.name() == ElectrumV2Seed.name():
            output["mnemonic_type"] = kwargs.get("mnemonic_type")
        click.echo(json.dumps(
            output, indent=kwargs.get("indent", 4), ensure_ascii=kwargs.get("ensure_ascii", False)
        ))

    except Exception as exception:
        click.echo(click.style(f"Error: {str(exception)}"), err=True)
        sys.exit()
