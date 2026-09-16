#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from .algorand import AlgorandHD
from .bip32 import BIP32HD
from .bip44 import BIP44HD
from .bip49 import BIP49HD
from .bip84 import BIP84HD
from .bip86 import BIP86HD
from .bip141 import BIP141HD
from .cardano import CardanoHD
from .electrum import (
    ElectrumV1HD, ElectrumV2HD
)
from .monero import MoneroHD
from ..exceptions import HDError
from .ihd import IHD


class HDS:
    """
    A class that manages a dictionary of hd classes.

    This class provides methods to retrieve names and classes of various hd implementations,
    as well as methods to validate and access specific hd classes by name.

    Here are available hd names and classes:

    +--------------+--------------------------------------------------+
    | Name         | Class                                            |
    +==============+==================================================+
    | Algorand     | :class:`hdwallet.hds.algorand.AlgorandHD`        |
    +--------------+--------------------------------------------------+
    | BIP32        | :class:`hdwallet.hds.bip32.BIP32HD`              |
    +--------------+--------------------------------------------------+
    | BIP44        | :class:`hdwallet.hds.bip44.BIP44HD`              |
    +--------------+--------------------------------------------------+
    | BIP49        | :class:`hdwallet.hds.bip49.BIP49HD`              |
    +--------------+--------------------------------------------------+
    | BIP84        | :class:`hdwallet.hds.bip84.BIP84HD`              |
    +--------------+--------------------------------------------------+
    | BIP86        | :class:`hdwallet.hds.bip86.BIP86HD`              |
    +--------------+--------------------------------------------------+
    | BIP141       | :class:`hdwallet.hds.bip141.BIP141HD`            |
    +--------------+--------------------------------------------------+
    | Cardano      | :class:`hdwallet.hds.cardano.CardanoHD`          |
    +--------------+--------------------------------------------------+
    | Electrum-V1  | :class:`hdwallet.hds.electrum.v1.ElectrumV1HD`   |
    +--------------+--------------------------------------------------+
    | Electrum-V2  | :class:`hdwallet.hds.electrum.v2.ElectrumV2HD`   |
    +--------------+--------------------------------------------------+
    | Monero       | :class:`hdwallet.hds.monero.MoneroHD`            |
    +--------------+--------------------------------------------------+

    """

    dictionary: Dict[str, Type[IHD]] = {
        AlgorandHD.name(): AlgorandHD,
        BIP32HD.name(): BIP32HD,
        BIP44HD.name(): BIP44HD,
        BIP49HD.name(): BIP49HD,
        BIP84HD.name(): BIP84HD,
        BIP86HD.name(): BIP86HD,
        BIP141HD.name(): BIP141HD,
        CardanoHD.name(): CardanoHD,
        ElectrumV1HD.name(): ElectrumV1HD,
        ElectrumV2HD.name(): ElectrumV2HD,
        MoneroHD.name(): MoneroHD
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get a list of names from the dictionary attribute of the class.

        :return: List of names from the class dictionary.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IHD]]:
        """
        Get a list of classes from the dictionary attribute of the class.

        :return: List of classes from the class dictionary.
        :rtype: List[Type[IHD]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def hd(cls, name: str) -> Type[IHD]:
        """
        Get the HD class type from the dictionary attribute of the class based on the given name.

        :param name: The name of the HD class to retrieve.
        :type name: str

        :return: The HD class type corresponding to the given name.
        :rtype: Type[IHD]
        """

        if not cls.is_hd(name=name):
            raise HDError(
                "Invalid HD name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_hd(cls, name: str) -> bool:
        """
        Check if the given name corresponds to an HD class in the class dictionary.

        :param name: The name to check.
        :type name: str

        :return: True if the name corresponds to an HD class, False otherwise.
        :rtype: bool
        """
        return name in cls.names()


__all__: List[str] = [
    "IHD", "HDS"
] + [
    cls.__name__ for cls in HDS.classes()
]
