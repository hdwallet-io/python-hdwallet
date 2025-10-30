#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Type
from bip38 import BIP38

import json
import click
import sys

from ..entropies import ENTROPIES
from ..mnemonics import MNEMONICS
from ..seeds import SEEDS
from ..hds import HDS
from ..derivations import DERIVATIONS
from ..cryptocurrencies import (
    ICryptocurrency, get_cryptocurrency
)

from ..hdwallet import HDWallet
from . import BIP38_CRYPTOCURRENCIES


def dump(**kwargs) -> None:
    try:
        cryptocurrency: Type[ICryptocurrency] = get_cryptocurrency(
            symbol=kwargs.get("symbol")
        )
        if not HDS.is_hd(name=kwargs.get("hd")):
            click.echo(click.style(
                f"Wrong HD name, (expected={HDS.names()}, got='{kwargs.get('hd')}')"
            ), err=True)
            sys.exit()
        if not DERIVATIONS.is_derivation(name=kwargs.get("derivation")):
            click.echo(click.style(
                f"Wrong from derivation name, (expected={DERIVATIONS.names()}, got='{kwargs.get('derivation')}')"
            ), err=True)
            sys.exit()
        if not cryptocurrency.NETWORKS.is_network(network=kwargs.get("network")):
            click.echo(click.style(
                f"Invalid {cryptocurrency.NAME} cryptocurrency network, "
                f"(expected={cryptocurrency.NETWORKS.get_networks()}, got='{kwargs.get('network')}')"
            ), err=True)
            sys.exit()

        semantic = kwargs.get("semantic")
        if semantic is None:
            if kwargs.get("hd") in [
                "BIP32", "BIP44", "BIP86", "Cardano"
            ]:
                semantic = cryptocurrency.DEFAULT_SEMANTIC
            elif kwargs.get("hd") == "BIP49":
                semantic = "p2wpkh-in-p2sh"
            elif kwargs.get("hd") in ["BIP84", "BIP141"]:
                semantic = "p2wpkh"

        hdwallet: HDWallet = HDWallet(
            cryptocurrency=cryptocurrency,
            hd=HDS.hd(name=kwargs.get("hd")),
            network=kwargs.get("network"),
            public_key_type=kwargs.get("public_key_type"),
            language=kwargs.get("language"),
            passphrase=kwargs.get("passphrase"),
            cardano_type=kwargs.get("cardano_type"),
            address_type=kwargs.get("address_type"),
            staking_public_key=kwargs.get("staking_public_key"),
            mode=kwargs.get("mode"),
            mnemonic_type=kwargs.get("mnemonic_type"),
            checksum=kwargs.get("checksum"),
            payment_id=kwargs.get("payment_id"),
            semantic=semantic
        )

        if kwargs.get("entropy"):
            if not ENTROPIES.is_entropy(name=kwargs.get("entropy_client")):
                click.echo(click.style(
                    f"Wrong entropy client, (expected={ENTROPIES.names()}, got='{kwargs.get('entropy_client')}')"
                ), err=True)
                sys.exit()
            hdwallet.from_entropy(
                entropy=ENTROPIES.entropy(name=kwargs.get("entropy_client")).__call__(
                    entropy=kwargs.get("entropy")
                )
            )
        elif kwargs.get("mnemonic"):
            if not MNEMONICS.is_mnemonic(name=kwargs.get("mnemonic_client")):
                click.echo(click.style(
                    f"Wrong mnemonic client, (expected={MNEMONICS.names()}, got='{kwargs.get('mnemonic_client')}')"
                ), err=True)
                sys.exit()
            if kwargs.get("mnemonic_client") == "Electrum-V2":
                hdwallet.from_mnemonic(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("mnemonic_client")).__call__(
                        mnemonic=kwargs.get("mnemonic"),
                        mnemonic_type=kwargs.get("mnemonic_type")
                    )
                )
            else:
                hdwallet.from_mnemonic(
                    mnemonic=MNEMONICS.mnemonic(name=kwargs.get("mnemonic_client")).__call__(
                        mnemonic=kwargs.get("mnemonic")
                    )
                )
        elif kwargs.get("seed"):
            if not SEEDS.is_seed(name=kwargs.get("seed_client")):
                click.echo(click.style(
                    f"Wrong seed client, (expected={SEEDS.names()}, got='{kwargs.get('seed_client')}')"
                ), err=True)
                sys.exit()
            if kwargs.get("seed_client") == "Cardano" and kwargs.get("cardano_type"):
                # If a specific cardano_type is specified, we must override the CardanoSeed default
                hdwallet.from_seed(
                    seed=SEEDS.seed(name=kwargs.get("seed_client")).__call__(
                        seed=kwargs.get("seed"),
                        cardano_type=kwargs.get("cardano_type")
                    )
                )
            else:
                hdwallet.from_seed(
                    seed=SEEDS.seed(name=kwargs.get("seed_client")).__call__(
                        seed=kwargs.get("seed")
                    )
                )
        elif kwargs.get("xprivate_key"):
            hdwallet.from_xprivate_key(
                xprivate_key=kwargs.get("xprivate_key"),
                encoded=kwargs.get("encoded"),
                strict=kwargs.get("strict")
            )
        elif kwargs.get("xpublic_key"):
            hdwallet.from_xpublic_key(
                xpublic_key=kwargs.get("xpublic_key"),
                encoded=kwargs.get("encoded"),
                strict=kwargs.get("strict")
            )
        elif kwargs.get("private_key"):
            hdwallet.from_private_key(
                private_key=kwargs.get("private_key")
            )
        elif kwargs.get("wif"):

            _wif = kwargs.get("wif")

            if kwargs.get("bip38"):

                bip38: BIP38 = BIP38(
                    cryptocurrency=BIP38_CRYPTOCURRENCIES[cryptocurrency.NAME], network=kwargs.get("network")
                )
                _wif = bip38.decrypt(encrypted_wif=_wif, passphrase=kwargs.get("passphrase"))

            hdwallet.from_wif(
                wif=_wif
            )

        elif kwargs.get("public_key"):
            hdwallet.from_public_key(
                public_key=kwargs.get("public_key")
            )
        elif kwargs.get("spend_private_key"):
            hdwallet.from_spend_private_key(
                spend_private_key=kwargs.get("spend_private_key")
            )
        elif kwargs.get("view_private_key") and kwargs.get("spend_public_key"):
            hdwallet.from_watch_only(
                view_private_key=kwargs.get("view_private_key"),
                spend_public_key=kwargs.get("spend_public_key")
            )

        if (
            kwargs.get("entropy") or
            kwargs.get("mnemonic") or
            kwargs.get("seed") or
            kwargs.get("xprivate_key") or
            kwargs.get("xpublic_key") or
            (kwargs.get("private_key") and kwargs.get("hd") in ["Electrum-V1", "Monero"]) or
            (kwargs.get("wif") and kwargs.get("hd") == "Electrum-V1") or
            kwargs.get("spend_private_key") or
            (kwargs.get("view_private_key") and kwargs.get("spend_public_key"))
        ):

            if kwargs.get("derivation") in [
                "BIP44", "BIP49", "BIP84", "BIP86"
            ]:
                hdwallet.from_derivation(
                    derivation=DERIVATIONS.derivation(name=kwargs.get("derivation")).__call__(
                        coin_type=cryptocurrency.COIN_TYPE,
                        account=kwargs.get("account"),
                        change=kwargs.get("change"),
                        address=kwargs.get("address")
                    )
                )
            elif kwargs.get("derivation") == "CIP1852":
                hdwallet.from_derivation(
                    derivation=DERIVATIONS.derivation(name=kwargs.get("derivation")).__call__(
                        coin_type=cryptocurrency.COIN_TYPE,
                        account=kwargs.get("account"),
                        role=kwargs.get("role"),
                        address=kwargs.get("address")
                    )
                )
            elif kwargs.get("derivation") == "Custom":
                hdwallet.from_derivation(
                    derivation=DERIVATIONS.derivation(name=kwargs.get("derivation")).__call__(
                        path=kwargs.get("path", "m/"),
                        indexes=kwargs.get("indexes", [])
                    )
                )
            elif kwargs.get("derivation") == "Electrum":
                hdwallet.from_derivation(
                    derivation=DERIVATIONS.derivation(name=kwargs.get("derivation")).__call__(
                        change=kwargs.get("change"),
                        address=kwargs.get("address")
                    )
                )
            elif kwargs.get("derivation") == "Monero":
                hdwallet.from_derivation(
                    derivation=DERIVATIONS.derivation(name=kwargs.get("derivation")).__call__(
                        minor=kwargs.get("minor"),
                        major=kwargs.get("major")
                    )
                )

        click.echo(json.dumps(
            hdwallet.dump(exclude=set(kwargs.get("exclude").split(","))), indent=4, ensure_ascii=False
        ))

    except Exception as exception:
        click.echo(click.style(
            f"Error: {str(exception)}"
        ), err=True)
        sys.exit()
