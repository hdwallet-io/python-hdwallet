#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from ..exceptions import DerivationError
from .bip44 import (  # noqa: F401
    BIP44Derivation, CHANGES
)
from .bip49 import BIP49Derivation
from .bip84 import BIP84Derivation
from .bip86 import BIP86Derivation
from .cip1852 import (  # noqa: F401
    CIP1852Derivation, ROLES
)
from .custom import CustomDerivation
from .electrum import ElectrumDerivation
from .monero import MoneroDerivation
from .hdw import HDWDerivation
from .iderivation import IDerivation


class DERIVATIONS:
    """
    A class that manages a dictionary of derivation classes.

    This class provides methods to retrieve names and classes of various derivation implementations,
    as well as methods to validate and access specific derivation classes by name.

    Here are available entropy names and classes:

    +--------------+-------------------------------------------------------------+
    | Name         | Class                                                       |
    +==============+=============================================================+
    | BIP44        | :class:`hdwallet.derivations.bip44.BIP44Derivation`         |
    +--------------+-------------------------------------------------------------+
    | BIP49        | :class:`hdwallet.derivations.bip49.BIP49Derivation`         |
    +--------------+-------------------------------------------------------------+
    | BIP84        | :class:`hdwallet.derivations.bip84.BIP84Derivation`         |
    +--------------+-------------------------------------------------------------+
    | BIP86        | :class:`hdwallet.derivations.bip86.BIP86Derivation`         |
    +--------------+-------------------------------------------------------------+
    | CIP1852      | :class:`hdwallet.derivations.cip1852.CIP1852Derivation`     |
    +--------------+-------------------------------------------------------------+
    | Custom       | :class:`hdwallet.derivations.custom.CustomDerivation`       |
    +--------------+-------------------------------------------------------------+
    | Electrum     | :class:`hdwallet.derivations.electrum.ElectrumDerivation`   |
    +--------------+-------------------------------------------------------------+
    | Monero       | :class:`hdwallet.derivations.monero.MoneroDerivation`       |
    +--------------+-------------------------------------------------------------+
    | HDW          | :class:`hdwallet.derivations.hdw.HDWDerivation`             |
    +--------------+-------------------------------------------------------------+
    """

    dictionary: Dict[str, Type[IDerivation]] = {
        BIP44Derivation.name(): BIP44Derivation,
        BIP49Derivation.name(): BIP49Derivation,
        BIP84Derivation.name(): BIP84Derivation,
        BIP86Derivation.name(): BIP86Derivation,
        CIP1852Derivation.name(): CIP1852Derivation,
        CustomDerivation.name(): CustomDerivation,
        ElectrumDerivation.name(): ElectrumDerivation,
        MoneroDerivation.name(): MoneroDerivation,
        HDWDerivation.name(): HDWDerivation
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the list of derivation class names.

        :return: A list of derivation class names.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IDerivation]]:
        """
        Get the list of derivation classes.

        :return: A list of derivation classes.
        :rtype: List[Type[IDerivation]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def derivation(cls, name: str) -> Type[IDerivation]:
        """
        Retrieve an derivation class by its name.

        :param name: The name of the derivation class.
        :type name: str

        :return: The derivation class corresponding to the given name.
        :rtype: Type[IDerivation]
        """

        if not cls.is_derivation(name=name):
            raise DerivationError(
                "Invalid derivation name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_derivation(cls, name: str) -> bool:
        """
        Check if a given name is a valid derivation name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is valid, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


__all__: List[str] = [
    "IDerivation", "CHANGES", "ROLES", "DERIVATIONS"
] + [
    cls.__name__ for cls in DERIVATIONS.classes()
]
