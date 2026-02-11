#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from .iseed import ISeed
from ..exceptions import SeedError
from .algorand import AlgorandSeed
from .bip39 import BIP39Seed
from .slip39 import SLIP39Seed
from .cardano import CardanoSeed
from .electrum import (
    ElectrumV1Seed, ElectrumV2Seed
)
from .monero import MoneroSeed


class SEEDS:
    """
    A class that manages a dictionary of seeds classes.

    This class provides methods to retrieve names and classes of various seeds implementations,
    as well as methods to validate and access specific seeds classes by name.

    Here are available SEED names:

    +--------------+------------------------------------------------------+
    | Name         | Class                                                |
    +==============+======================================================+
    | Algorand     |  :class:`hdwallet.seeds.algorand.AlgorandSeed`       |
    +--------------+------------------------------------------------------+
    | BIP39        |  :class:`hdwallet.seeds.bip39.BIP39Seed`             |
    +--------------+------------------------------------------------------+
    | SLIP39       |  :class:`hdwallet.seeds.sli39.SLIP39Seed`             |
    +--------------+------------------------------------------------------+
    | Cardano      |  :class:`hdwallet.seeds.cardano.CardanoSeed`         |
    +--------------+------------------------------------------------------+
    | Electrum-V1  |  :class:`hdwallet.seeds.electrum.v1.ElectrumV1Seed`  |
    +--------------+------------------------------------------------------+
    | Electrum-V2  |  :class:`hdwallet.seeds.electrum.v2.ElectrumV2Seed`  |
    +--------------+------------------------------------------------------+
    | Monero       |  :class:`hdwallet.seeds.monero.MoneroSeed`           |
    +--------------+------------------------------------------------------+
    """

    dictionary: Dict[str, Type[ISeed]] = {
        AlgorandSeed.name(): AlgorandSeed,
        BIP39Seed.name(): BIP39Seed,
        SLIP39Seed.name(): SLIP39Seed,
        CardanoSeed.name(): CardanoSeed,
        ElectrumV1Seed.name(): ElectrumV1Seed,
        ElectrumV2Seed.name(): ElectrumV2Seed,
        MoneroSeed.name(): MoneroSeed
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the list of seed class names.

        :return: A list of seed class names.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[ISeed]]:
        """
        Get the list of seed classes.

        :return: A list of seed classes.
        :rtype: List[Type[ISeed]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def seed(cls, name: str) -> Type[ISeed]:
        """
        Retrieve an seed class by its name.

        :param name: The name of the seed class.
        :type name: str

        :return: The seed class corresponding to the given name.
        :rtype: Type[ISeed]
        """

        if not cls.is_seed(name=name):
            raise SeedError(
                "Invalid seed name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_seed(cls, name) -> bool:
        """
        Check if a given name is a valid seed name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is valid, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


__all__: List[str] = [
    "ISeed", "SEEDS"
] + [
    cls.__name__ for cls in SEEDS.classes()
]
