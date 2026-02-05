#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from ..exceptions import AddressError
from .algorand import AlgorandAddress
from .aptos import AptosAddress
from .avalanche import AvalancheAddress
from .bitcoincash import BitcoinCashAddress
from .cardano import CardanoAddress
from .cosmos import CosmosAddress
from .eos import EOSAddress
from .ergo import ErgoAddress
from .ethereum import EthereumAddress
from .filecoin import FilecoinAddress
from .harmony import HarmonyAddress
from .icon import IconAddress
from .injective import InjectiveAddress
from .monero import MoneroAddress
from .multiversx import MultiversXAddress
from .nano import NanoAddress
from .near import NearAddress
from .neo import NeoAddress
from .okt_chain import OKTChainAddress
from .p2pkh import P2PKHAddress
from .p2sh import P2SHAddress
from .p2tr import P2TRAddress
from .p2wpkh import P2WPKHAddress
from .p2wpkh_in_p2sh import P2WPKHInP2SHAddress
from .p2wsh import P2WSHAddress
from .p2wsh_in_p2sh import P2WSHInP2SHAddress
from .ripple import RippleAddress
from .solana import SolanaAddress
from .stellar import StellarAddress
from .sui import SuiAddress
from .tezos import TezosAddress
from .tron import TronAddress
from .xinfin import XinFinAddress
from .zilliqa import ZilliqaAddress
from .iaddress import IAddress


class ADDRESSES:
    """
    A class that manages a dictionary of address classes.

    This class provides methods to retrieve names and classes of various address implementations,
    as well as methods to validate and access specific address classes by name.

    Here are available address names and classes:

    +-----------------+------------------------------------------------------------------+
    | Name            | Class                                                            |
    +=================+==================================================================+
    | Algorand        | :class:`hdwallet.addresses.algorand.AlgorandAddress`             |
    +-----------------+------------------------------------------------------------------+
    | Aptos           | :class:`hdwallet.addresses.aptos.AptosAddress`                   |
    +-----------------+------------------------------------------------------------------+
    | Avalanche       | :class:`hdwallet.addresses.avalanche.AvalancheAddress`           |
    +-----------------+------------------------------------------------------------------+
    | BitcoinCash     | :class:`hdwallet.addresses.bitcoincash.BitcoinCash`              |
    +-----------------+------------------------------------------------------------------+
    | Cardano         | :class:`hdwallet.addresses.cardano.CardanoAddress`               |
    +-----------------+------------------------------------------------------------------+
    | Cosmos          | :class:`hdwallet.addresses.cosmos.CosmosAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | EOS             | :class:`hdwallet.addresses.eos.EOSAddress`                       |
    +-----------------+------------------------------------------------------------------+
    | Ergo            | :class:`hdwallet.addresses.ergo.ErgoAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | Ethereum        | :class:`hdwallet.addresses.ethereum.EthereumAddress`             |
    +-----------------+------------------------------------------------------------------+
    | Filecoin        | :class:`hdwallet.addresses.filecoin.FilecoinAddress`             |
    +-----------------+------------------------------------------------------------------+
    | Harmony         | :class:`hdwallet.addresses.harmony.HarmonyAddress`               |
    +-----------------+------------------------------------------------------------------+
    | Icon            | :class:`hdwallet.addresses.icon.IconAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | Injective       | :class:`hdwallet.addresses.injective.InjectiveAddress`           |
    +-----------------+------------------------------------------------------------------+
    | Monero          | :class:`hdwallet.addresses.monero.MoneroAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | MultiversX      | :class:`hdwallet.addresses.multiversx.MultiversXAddress`         |
    +-----------------+------------------------------------------------------------------+
    | Nano            | :class:`hdwallet.addresses.nano.NanoAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | Near            | :class:`hdwallet.addresses.near.NearAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | Neo             | :class:`hdwallet.addresses.neo.NeoAddress`                       |
    +-----------------+------------------------------------------------------------------+
    | OKT-Chain       | :class:`hdwallet.addresses.okt_chain.OKTChainAddress`            |
    +-----------------+------------------------------------------------------------------+
    | P2PKH           | :class:`hdwallet.addresses.p2pkh.P2PKHAddress`                   |
    +-----------------+------------------------------------------------------------------+
    | P2SH            | :class:`hdwallet.addresses.p2sh.P2SHAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | P2TR            | :class:`hdwallet.addresses.p2tr.P2TRAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | P2WPKH          | :class:`hdwallet.addresses.p2wpkh.P2WPKHAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | P2WPKH-In-P2SH  | :class:`hdwallet.addresses.p2wpkh_in_p2sh.P2WPKHInP2SHAddress`   |
    +-----------------+------------------------------------------------------------------+
    | P2WSH           | :class:`hdwallet.addresses.p2wsh.P2WSHAddress`                   |
    +-----------------+------------------------------------------------------------------+
    | P2WSH-In-P2SH   | :class:`hdwallet.addresses.p2wsh_in_p2sh.P2WSHInP2SHAddress`     |
    +-----------------+------------------------------------------------------------------+
    | Ripple          | :class:`hdwallet.addresses.ripple.RippleAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | Solana          | :class:`hdwallet.addresses.solana.SolanaAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | Stellar         | :class:`hdwallet.addresses.stellar.StellarAddress`               |
    +-----------------+------------------------------------------------------------------+
    | Sui             | :class:`hdwallet.addresses.sui.SuiAddress`                       |
    +-----------------+------------------------------------------------------------------+
    | Tezos           | :class:`hdwallet.addresses.tezos.TezosAddress`                   |
    +-----------------+------------------------------------------------------------------+
    | Tron            | :class:`hdwallet.addresses.tron.TronAddress`                     |
    +-----------------+------------------------------------------------------------------+
    | XinFin          | :class:`hdwallet.addresses.xinfin.XinFinAddress`                 |
    +-----------------+------------------------------------------------------------------+
    | Zilliqa         | :class:`hdwallet.addresses.zilliqa.ZilliqaAddress`               |
    +-----------------+------------------------------------------------------------------+

    """

    dictionary: Dict[str, Type[IAddress]] = {
        AlgorandAddress.name(): AlgorandAddress,
        AptosAddress.name(): AptosAddress,
        AvalancheAddress.name(): AvalancheAddress,
        BitcoinCashAddress.name(): BitcoinCashAddress,
        CardanoAddress.name(): CardanoAddress,
        CosmosAddress.name(): CosmosAddress,
        EOSAddress.name(): EOSAddress,
        ErgoAddress.name(): ErgoAddress,
        EthereumAddress.name(): EthereumAddress,
        FilecoinAddress.name(): FilecoinAddress,
        HarmonyAddress.name(): HarmonyAddress,
        IconAddress.name(): IconAddress,
        InjectiveAddress.name(): InjectiveAddress,
        MoneroAddress.name(): MoneroAddress,
        MultiversXAddress.name(): MultiversXAddress,
        NanoAddress.name(): NanoAddress,
        NearAddress.name(): NearAddress,
        NeoAddress.name(): NeoAddress,
        OKTChainAddress.name(): OKTChainAddress,
        P2PKHAddress.name(): P2PKHAddress,
        P2SHAddress.name(): P2SHAddress,
        P2TRAddress.name(): P2TRAddress,
        P2WPKHAddress.name(): P2WPKHAddress,
        P2WPKHInP2SHAddress.name(): P2WPKHInP2SHAddress,
        P2WSHAddress.name(): P2WSHAddress,
        P2WSHInP2SHAddress.name(): P2WSHInP2SHAddress,
        RippleAddress.name(): RippleAddress,
        SolanaAddress.name(): SolanaAddress,
        StellarAddress.name(): StellarAddress,
        SuiAddress.name(): SuiAddress,
        TezosAddress.name(): TezosAddress,
        TronAddress.name(): TronAddress,
        XinFinAddress.name(): XinFinAddress,
        ZilliqaAddress.name(): ZilliqaAddress
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the list of address class names.

        :return: A list of address class names.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IAddress]]:
        """
        Get the list of address classes.

        :return: A list of address classes.
        :rtype: List[Type[IAddress]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def address(cls, name: str) -> Type[IAddress]:
        """
        Retrieve an address class by its name.

        :param name: The name of the address class.
        :type name: str

        :return: The address class corresponding to the given name.
        :rtype: Type[IAddress]
        """

        if not cls.is_address(name=name):
            raise AddressError(
                "Invalid address name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_address(cls, name: str) -> bool:
        """
        Check if a given name is a valid address name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is valid, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


__all__: List[str] = [
    "IAddress", "ADDRESSES"
] + [
    cls.__name__ for cls in ADDRESSES.classes()
]
