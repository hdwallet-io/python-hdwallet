#!/usr/bin/env python3

# Copyright © 2020-2023, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from ..exceptions import MnemonicError
from .algorand import (  # noqa: F401
    AlgorandMnemonic, ALGORAND_MNEMONIC_WORDS, ALGORAND_MNEMONIC_LANGUAGES
)
from .bip39 import (  # noqa: F401
    BIP39Mnemonic, BIP39_MNEMONIC_WORDS, BIP39_MNEMONIC_LANGUAGES
)
from .slip39 import (  # noqa: F401
    SLIP39Mnemonic, SLIP39_MNEMONIC_WORDS, SLIP39_MNEMONIC_LANGUAGES
)
from .electrum import (  # noqa: F401
    ElectrumV1Mnemonic, ELECTRUM_V1_MNEMONIC_WORDS, ELECTRUM_V1_MNEMONIC_LANGUAGES,
    ElectrumV2Mnemonic, ELECTRUM_V2_MNEMONIC_WORDS, ELECTRUM_V2_MNEMONIC_LANGUAGES, ELECTRUM_V2_MNEMONIC_TYPES
)
from .monero import (  # noqa: F401
    MoneroMnemonic, MONERO_MNEMONIC_WORDS, MONERO_MNEMONIC_LANGUAGES
)
from .imnemonic import IMnemonic


class MNEMONICS:
    """
    A class that manages a dictionary of mnemonic classes.

    This class provides methods to retrieve names and classes of various mnemonic implementations,
    as well as methods to validate and access specific mnemonic classes by name.

    Here are available mnemonic names and classes:

    +--------------+------------------------------------------------------------------------+
    | Name         | Class                                                                  |
    +==============+========================================================================+
    | Algorand     |  :class:`hdwallet.mnemonics.algorand.mnemonic.AlgorandMnemonic`        |
    +--------------+------------------------------------------------------------------------+
    | BIP39        |  :class:`hdwallet.mnemonics.bip39.mnemonic.BIP39Mnemonic`              |
    +--------------+------------------------------------------------------------------------+
    | SLIP39       |  :class:`hdwallet.mnemonics.slip39.mnemonic.SLIP39Mnemonic`            |
    +--------------+------------------------------------------------------------------------+
    | Electrum-V1  |  :class:`hdwallet.mnemonics.electrum.v1.mnemonic.ElectrumV1Mnemonic`   |
    +--------------+------------------------------------------------------------------------+
    | Electrum-V2  |  :class:`hdwallet.mnemonics.electrum.v2.mnemonic.ElectrumV2Mnemonic`   |
    +--------------+------------------------------------------------------------------------+
    | Monero       |  :class:`hdwallet.mnemonics.monero.mnemonic.MoneroMnemonic`            |
    +--------------+------------------------------------------------------------------------+
    """

    dictionary: Dict[str, Type[IMnemonic]] = {
        AlgorandMnemonic.name(): AlgorandMnemonic,
        BIP39Mnemonic.name(): BIP39Mnemonic,
        SLIP39Mnemonic.name(): SLIP39Mnemonic,
        ElectrumV1Mnemonic.name(): ElectrumV1Mnemonic,
        ElectrumV2Mnemonic.name(): ElectrumV2Mnemonic,
        MoneroMnemonic.name(): MoneroMnemonic,
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the list of mnemonic class names.

        :return: A list of mnemonic class names.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IMnemonic]]:
        """
        Get the list of mnemonic classes.

        :return: A list of mnemonic classes.
        :rtype: List[Type[IMnemonic]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def mnemonic(cls, name: str) -> Type[IMnemonic]:
        """
        Retrieve an mnemonic class by its name.

        :param name: The name of the mnemonic class.
        :type name: str

        :return: The mnemonic class corresponding to the given name.
        :rtype: Type[IMnemonic]
        """

        if not cls.is_mnemonic(name=name):
            raise MnemonicError(
                "Invalid mnemonic name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_mnemonic(cls, name) -> bool:
        """
        Check if a given name is a valid mnemonic name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is valid, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


__all__: List[str] = [
    "IMnemonic",
    "ALGORAND_MNEMONIC_WORDS", "ALGORAND_MNEMONIC_LANGUAGES",
    "BIP39_MNEMONIC_WORDS", "BIP39_MNEMONIC_LANGUAGES",
    "SLIP39_MNEMONIC_WORDS", "SLIP39_MNEMONIC_LANGUAGES",
    "ELECTRUM_V1_MNEMONIC_WORDS", "ELECTRUM_V1_MNEMONIC_LANGUAGES",
    "ELECTRUM_V2_MNEMONIC_WORDS", "ELECTRUM_V2_MNEMONIC_LANGUAGES", "ELECTRUM_V2_MNEMONIC_TYPES",
    "MONERO_MNEMONIC_WORDS", "MONERO_MNEMONIC_LANGUAGES",
    "MNEMONICS"
] + [
    cls.__name__ for cls in MNEMONICS.classes()
]
