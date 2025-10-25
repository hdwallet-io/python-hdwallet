#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from click_aliases import ClickAliasedGroup

import click

from ..cryptocurrencies import Cardano
from ..mnemonics import ELECTRUM_V2_MNEMONIC_TYPES
from ..consts import (
    PUBLIC_KEY_TYPES, MODES
)

from .. import __version__

from .generate.entropy import generate_entropy
from .generate.mnemonic import generate_mnemonic
from .generate.seed import generate_seed
from .dump import dump
from .dumps import dumps
from .list.cryptocurrencies import list_cryptocurrencies
from .list.languages import list_languages
from .list.strengths import list_strengths


def process_kwargs(kwargs):
    """Process mnemonic arguments handling both multiple flags and explicit \\n sequences."""
    if kwargs.get("mnemonic"):
        # Join multiple mnemonic arguments, then split on any literal raw r"\n" and rejoin
        combined = "\n".join(kwargs["mnemonic"])
        kwargs["mnemonic"] = "\n".join(combined.split(r'\n'))
    return kwargs


def current_version(
    context: click.core.Context, option: click.core.Option, value: bool
) -> None:
    if not value or context.resilient_parsing:
        return
    click.echo(__version__)
    context.exit()


@click.group(
    cls=ClickAliasedGroup,
    options_metavar="[OPTIONS]",
    context_settings={
        "help_option_names": ["-h", "--help"]
    }
)
@click.option(
    "-v", "--version",
    is_flag=True,
    callback=current_version,
    expose_value=False,
    help="Show HDWallet version and exit"
)
def cli_main():
    pass


@cli_main.group(
    "generate",
    aliases=["g"],
    cls=ClickAliasedGroup,
    options_metavar="[OPTIONS]",
    short_help="Select Generate for HDWallet",
    invoke_without_command=True
)
@click.pass_context
def generate(context: click.core.Context) -> None:
    if context.invoked_subcommand is None:
        pass


@generate.command(
    "entropy",
    aliases=["e"],
    options_metavar="[OPTIONS]",
    short_help="Select Entropy for generation entropy"
)
@click.option(
    "-c", "--client", type=str, default="BIP39", help="Set Entropy client", show_default=True
)
@click.option(
    "-s", "--strength", type=int, default=None, help="Set Strength for entropy", show_default=True
)
def cli_entropy(**kwargs) -> None:
    return generate_entropy(**kwargs)


@generate.command(
    "mnemonic",
    aliases=["m"],
    options_metavar="[OPTIONS]",
    short_help="Select Mnemonic for generation mnemonic"
)
@click.option(
    "-c", "--client", type=str, default="BIP39", help="Set Mnemonic client", show_default=True
)
@click.option(
    "-l", "--language", type=str, default=None, help="Set Mnemonic language", show_default=True
)
@click.option(
    "-p", "--passphrase", type=str, default=None, help="Set Mnemonic passphrase for SLIP39", show_default=True
)
@click.option(
    "-t", "--tabulate", type=int, default=False, help="Set Mnemonic tabulation SLIP39", show_default=True
)
# Sources of entropy for the mnemonic; raw 'entropy', 'words', or another 'mnemonic' of 'mnemonic_type'
@click.option(
    "-e", "--entropy", type=str, default=None, help="Set Mnemonic entropy", show_default=True
)
@click.option(
    "-w", "--words", type=int, default=None, help="Set Mnemonic words", show_default=True
)
@click.option(
    "-mc", "--mnemonic-client", type=str, default="BIP39", help="Select entropy Mnemonic client", show_default=True
)
@click.option(
    "-m", "--mnemonic", multiple=True, help="Set entropy Mnemonic(s)"
)
@click.option(
    "-mt", "--mnemonic-type", type=str, default="standard", help="Set Mnemonic type for Electrum-V2", show_default=True
)
@click.option(
    "-mp", "--mnemonic-passphrase", type=str, default=None, help="Set entropy Mnemonic passphrase", show_default=True
)
@click.option(
    "-max", "--max-attempts", type=int, default=(10 ** 60), help="Set Max attempts for Electrum-V2", show_default=True
)
@click.option(
    "-cs", "--checksum", type=bool, default=False, help="Set Checksum for Monero", show_default=True
)
def cli_mnemonic(**kwargs) -> None:
    return generate_mnemonic(**kwargs)


@generate.command(
    "seed",
    aliases=["s"],
    options_metavar="[OPTIONS]",
    short_help="Select Seed for generation seed"
)
@click.option(
    "-c", "--client", type=str, default="BIP39", help="Set Seed client", show_default=True
)
@click.option(
    "-m", "--mnemonic", multiple=True, help="Set Seed mnemonic(s)"
)
@click.option(
    "-l", "--language", type=str, default=None, help="Set Mnemonic language", show_default=True
)
@click.option(
    "-p", "--passphrase", type=str, default=None, help="Set Seed passphrase", show_default=True
)
@click.option(
    "-ct", "--cardano-type", type=str, default=Cardano.TYPES.BYRON_ICARUS, help="Set Cardano Seed type", show_default=True
)
@click.option(
    "-mt", "--mnemonic-type", type=str, default="standard", help="Set Mnemonic type for Electrum-V2", show_default=True
)
def cli_seed(**kwargs) -> None:
    return generate_seed(**process_kwargs(kwargs))


@cli_main.command(
    "dump", aliases=["d"], options_metavar="[OPTIONS]", short_help="Select Dump hdwallet keys"
)
@click.option(
    "-sym", "--symbol", type=str, default="BTC", help="Set Cryptocurrency ticker symbol", show_default=True
)
@click.option(
    "-h", "--hd", type=str, default="BIP44", help="Select HD", show_default=True
)
@click.option(
    "-n", "--network", type=str, default="mainnet", help="Select Network type", show_default=True
)
@click.option(
    "-ec", "--entropy-client", type=str, default="BIP39", help="Select Entropy client", show_default=True
)
@click.option(
    "-e", "--entropy", type=str, default=None, help="Set Master key from Entropy hex string", show_default=True
)
@click.option(
    "-mc", "--mnemonic-client", type=str, default="BIP39", help="Select Mnemonic client", show_default=True
)
@click.option(
    "-m", "--mnemonic", multiple=True, help="Set Master key from mnemonic(s)"
)
@click.option(
    "-l", "--language", type=str, default="english", help="Select Language for mnemonic", show_default=True
)
@click.option(
    "-sc", "--seed-client", type=str, default="BIP39", help="Select Seed client", show_default=True
)
@click.option(
    "-s", "--seed", type=str, default=None, help="Set Master key from Seed hex string", show_default=True
)
@click.option(
    "-pp", "--passphrase", type=str, default=None, help="Set Passphrase for mnemonic & seed", show_default=True
)
@click.option(
    "-xprv", "--xprivate-key", type=str, default=None, help="Set Master key from XPrivate key", show_default=True
)
@click.option(
    "-xpub", "--xpublic-key", type=str, default=None, help="Set Master key from XPublic key", show_default=True
)
@click.option(
    "-enc", "--encoded", type=bool, default=True, help="Set Encoded for XPrivate & XPublic keys", show_default=True
)
@click.option(
    "-st", "--strict", type=bool, default=False, help="Set Strict for Root XPrivate & XPublic keys", show_default=True
)
@click.option(
    "-pkt", "--public-key-type", type=str, default=PUBLIC_KEY_TYPES.COMPRESSED, help="Select Public key type", show_default=True
)
@click.option(
    "-d", "--derivation", type=str, default="BIP44", help="Select Derivation name", show_default=True
)
@click.option(
    "-ac", "--account", type=str, default="0", help="Set Account index for derivation", show_default=True
)
@click.option(
    "-ch", "--change", type=str, default="0", help="Set Change index for derivation", show_default=True
)
@click.option(
    "-ecc", "--ecc", type=str, default="0", help="Set ECC index for HDW derivation", show_default=True
)
@click.option(
    "-ro", "--role", type=str, default="0", help="Set Role index for CIP1852 derivation", show_default=True
)
@click.option(
    "-ad", "--address", type=str, default="0", help="Set Address index for derivation", show_default=True
)
@click.option(
    "-mi", "--minor", type=str, default="1", help="Set Minor index for Monero derivation", show_default=True
)
@click.option(
    "-ma", "--major", type=str, default="0", help="Set Major index for Monero derivation", show_default=True
)
@click.option(
    "-p", "--path", type=str, default=None, help="Set Path for derivation", show_default=True
)
@click.option(
    "-i", "--indexes", type=list, default=[], help="Set Indexes for derivation", show_default=True
)
@click.option(
    "-prv", "--private-key", type=str, default=None, help="Set Private key", show_default=True
)
@click.option(
    "-w", "--wif", type=str, default=None, help="Set Wallet Import Format (WIF)", show_default=True
)
@click.option(
    "-b38", "--bip38", type=bool, default=False, help="Is BIP38 Encrypted Wallet Import Format", show_default=True
)
@click.option(
    "-pub", "--public-key", type=str, default=None, help="Set Public key", show_default=True
)
@click.option(
    "-sprv", "--spend-private-key", type=str, default=None, help="Set Spend Private key for Monero", show_default=True
)
@click.option(
    "-vprv", "--view-private-key", type=str, default=None, help="Set View Private key for Monero", show_default=True
)
@click.option(
    "-spub", "--spend-public-key", type=str, default=None, help="Set Spend Public key for Monero", show_default=True
)
@click.option(
    "-stpub", "--staking-public-key", type=str, default=None, help="Set Staking Public key for Cardano Shelley", show_default=True
)
@click.option(
    "-ct", "--cardano-type", type=str, default=Cardano.TYPES.SHELLEY_ICARUS, help="Select Cardano type", show_default=True
)
@click.option(
    "-at", "--address-type", type=str, default=None, help="Select Address type", show_default=True
)
@click.option(
    "-mo", "--mode", type=str, default=MODES.STANDARD, help="Select Mode of Electrum-V2", show_default=True
)
@click.option(
    "-mt", "--mnemonic-type", type=str, default=ELECTRUM_V2_MNEMONIC_TYPES.STANDARD, help="Select Mnemonic type of Electrum-V2", show_default=True
)
@click.option(
    "-cs", "--checksum", type=bool, default=False, help="Set Checksum for Monero", show_default=True
)
@click.option(
    "-se", "--semantic", type=str, default=None, help="Set Semantic for BIP141", show_default=True
)
@click.option(
    "-pi", "--payment-id", type=str, default=None, help="Set Payment ID for Monero", show_default=True
)
@click.option(
    "-ex", "--exclude", type=str, default="", help="Set Exclude keys from dumped", show_default=True
)
def cli_dump(**kwargs) -> None:  # cli_dumps(max_content_width=120)
    return dump(**process_kwargs(kwargs))


@cli_main.command(
    "dumps", aliases=["ds"], options_metavar="[OPTIONS]", short_help="Select Dumps hdwallet keys"
)
@click.option(
    "-sym", "--symbol", type=str, default="BTC", help="Set Cryptocurrency ticker symbol", show_default=True
)
@click.option(
    "-h", "--hd", type=str, default="BIP44", help="Select HD", show_default=True
)
@click.option(
    "-n", "--network", type=str, default="mainnet", help="Select Network type", show_default=True
)
@click.option(
    "-ec", "--entropy-client", type=str, default="BIP39", help="Select Entropy client", show_default=True
)
@click.option(
    "-e", "--entropy", type=str, default=None, help="Set Master key from Entropy hex string", show_default=True
)
@click.option(
    "-mc", "--mnemonic-client", type=str, default="BIP39", help="Select Mnemonic client", show_default=True
)
@click.option(
    "-m", "--mnemonic", multiple=True, help="Set Master key from mnemonic(s)"
)
@click.option(
    "-l", "--language", type=str, default="english", help="Select Language for mnemonic", show_default=True
)
@click.option(
    "-sc", "--seed-client", type=str, default="BIP39", help="Select Seed client", show_default=True
)
@click.option(
    "-s", "--seed", type=str, default=None, help="Set Master key from Seed hex string", show_default=True
)
@click.option(
    "-pp", "--passphrase", type=str, default=None, help="Set Passphrase for mnemonic & seed", show_default=True
)
@click.option(
    "-xprv", "--xprivate-key", type=str, default=None, help="Set Master key from XPrivate key", show_default=True
)
@click.option(
    "-xpub", "--xpublic-key", type=str, default=None, help="Set Master key from XPublic key", show_default=True
)
@click.option(
    "-enc", "--encoded", type=bool, default=True, help="Set Encoded for XPrivate & XPublic keys", show_default=True
)
@click.option(
    "-st", "--strict", type=bool, default=False, help="Set Strict for Root XPrivate & XPublic keys", show_default=True
)
@click.option(
    "-pkt", "--public-key-type", type=str, default=PUBLIC_KEY_TYPES.COMPRESSED, help="Select Public key type", show_default=True
)
@click.option(
    "-d", "--derivation", type=str, default="BIP44", help="Select Derivation name", show_default=True
)
@click.option(
    "-ac", "--account", type=str, default="0", help="Set Account index for derivation", show_default=True
)
@click.option(
    "-ch", "--change", type=str, default="0", help="Set Change index for derivation", show_default=True
)
@click.option(
    "-ecc", "--ecc", type=str, default="0", help="Set ECC index for HDW derivation", show_default=True
)
@click.option(
    "-ro", "--role", type=str, default="0", help="Set Role index for CIP1852 derivation", show_default=True
)
@click.option(
    "-ad", "--address", type=str, default="0", help="Set Address index for derivation", show_default=True
)
@click.option(
    "-mi", "--minor", type=str, default="1", help="Set Minor index for Monero derivation", show_default=True
)
@click.option(
    "-ma", "--major", type=str, default="0", help="Set Major index for Monero derivation", show_default=True
)
@click.option(
    "-p", "--path", type=str, default=None, help="Set Path for derivation", show_default=True
)
@click.option(
    "-i", "--indexes", type=list, default=[], help="Set Indexes for derivation", show_default=True
)
@click.option(
    "-prv", "--private-key", type=str, default=None, help="Set Private key", show_default=True
)
@click.option(
    "-w", "--wif", type=str, default=None, help="Set Wallet Import Format (WIF)", show_default=True
)
@click.option(
    "-b38", "--bip38", type=bool, default=False, help="Is BIP38 Encrypted Wallet Import Format", show_default=True
)
@click.option(
    "-pub", "--public-key", type=str, default=None, help="Set Public key", show_default=True
)
@click.option(
    "-sprv", "--spend-private-key", type=str, default=None, help="Set Spend Private key for Monero", show_default=True
)
@click.option(
    "-vprv", "--view-private-key", type=str, default=None, help="Set View Private key for Monero", show_default=True
)
@click.option(
    "-spub", "--spend-public-key", type=str, default=None, help="Set Spend Public key for Monero", show_default=True
)
@click.option(
    "-stpub", "--staking-public-key", type=str, default=None, help="Set Staking Public key for Cardano Shelley", show_default=True
)
@click.option(
    "-ct", "--cardano-type", type=str, default=Cardano.TYPES.SHELLEY_ICARUS, help="Select Cardano type", show_default=True
)
@click.option(
    "-at", "--address-type", type=str, default=None, help="Select Address type", show_default=True
)
@click.option(
    "-mo", "--mode", type=str, default=MODES.STANDARD, help="Select Mode of Electrum-V2", show_default=True
)
@click.option(
    "-mt", "--mnemonic-type", type=str, default=ELECTRUM_V2_MNEMONIC_TYPES.STANDARD, help="Select Mnemonic type of Electrum-V2", show_default=True
)
@click.option(
    "-cs", "--checksum", type=bool, default=False, help="Set Checksum for Monero", show_default=True
)
@click.option(
    "-se", "--semantic", type=str, default=None, help="Set Semantic for BIP141", show_default=True
)
@click.option(
    "-pi", "--payment-id", type=str, default=None, help="Set Payment ID for Monero", show_default=True
)
@click.option(
    "-ex", "--exclude", type=str, default="", help="Set Exclude keys from dumped", show_default=True
)
@click.option(
    "-f", "--format", type=str, default="csv", help="Show dumps format type", show_default=True
)
@click.option(
    "-in", "--include", type=str, default=None, help="Set Include keys from dumped", show_default=True
)
@click.option(
    "-inh", "--include-header", is_flag=True, help="Set Include header from dumped", show_default=True
)
@click.option(
    "-de", "--delimiter", type=str, default=" ", help="Set Delimiter for CSV", show_default=True
)
def cli_dumps(**kwargs) -> None:  # cli_dumps(max_content_width=120)
    return dumps(**process_kwargs(kwargs))


@cli_main.group(
    "list",
    aliases=["l"],
    cls=ClickAliasedGroup,
    options_metavar="[OPTIONS]",
    short_help="Select List for HDWallet information",
    invoke_without_command=True
)
def cli_list() -> None:
    pass


@cli_list.command(
    "cryptocurrencies",
    aliases=["c"],
    options_metavar="[OPTIONS]",
    short_help="List Available cryptocurrencies of HDWallet"
)
def cli_cryptocurrencies() -> None:
    return list_cryptocurrencies()


@cli_list.command(
    "languages",
    aliases=["l"],
    options_metavar="[OPTIONS]",
    short_help="List Languages of mnemonic words"
)
def cli_languages() -> None:
    return list_languages()


@cli_list.command(
    "strengths",
    aliases=["s"],
    options_metavar="[OPTIONS]",
    short_help="List Strengths of mnemonic words"
)
def cli_strengths() -> None:
    return list_strengths()
