#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from ..exceptions import EntropyError
from .algorand import (  # noqa: F401
    AlgorandEntropy, ALGORAND_ENTROPY_STRENGTHS
)
from .bip39 import (  # noqa: F401
    BIP39Entropy, BIP39_ENTROPY_STRENGTHS
)
from .slip39 import (  # noqa: F401
    SLIP39Entropy, SLIP39_ENTROPY_STRENGTHS
)
from .electrum import (  # noqa: F401
    ElectrumV1Entropy, ELECTRUM_V1_ENTROPY_STRENGTHS,
    ElectrumV2Entropy, ELECTRUM_V2_ENTROPY_STRENGTHS
)
from .monero import (  # noqa: F401
    MoneroEntropy, MONERO_ENTROPY_STRENGTHS
)
from .ientropy import IEntropy


class ENTROPIES:
    """
    A class that manages a dictionary of entropy classes.

    This class provides methods to retrieve names and classes of various entropy implementations,
    as well as methods to validate and access specific entropy classes by name.

    Here are available entropy names and classes:

    +--------------+-------------------------------------------------------------+
    | Name         | Class                                                       |
    +==============+=============================================================+
    | Algorand     |  :class:`hdwallet.entropies.algorand.AlgorandEntropy`       |
    +--------------+-------------------------------------------------------------+
    | BIP39        |  :class:`hdwallet.entropies.bip39.BIP39Entropy`             |
    +--------------+-------------------------------------------------------------+
    | SLIP39       |  :class:`hdwallet.entropies.bip39.SLIP39Entropy`            |
    +--------------+-------------------------------------------------------------+
    | Electrum-V1  |  :class:`hdwallet.entropies.electrum.v1.ElectrumV1Entropy`  |
    +--------------+-------------------------------------------------------------+
    | Electrum-V2  | :class:`hdwallet.entropies.electrum.v2.ElectrumV2Entropy`   |
    +--------------+-------------------------------------------------------------+
    | Monero       | :class:`hdwallet.entropies.monero.MoneroEntropy`            |
    +--------------+-------------------------------------------------------------+
    """

    dictionary: Dict[str, Type[IEntropy]] = {
        AlgorandEntropy.name(): AlgorandEntropy,
        BIP39Entropy.name(): BIP39Entropy,
        SLIP39Entropy.name(): SLIP39Entropy,
        ElectrumV1Entropy.name(): ElectrumV1Entropy,
        ElectrumV2Entropy.name(): ElectrumV2Entropy,
        MoneroEntropy.name(): MoneroEntropy
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the list of entropy class names.

        :return: A list of entropy class names.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IEntropy]]:
        """
        Get the list of entropy classes.

        :return: A list of entropy classes.
        :rtype: List[Type[IEntropy]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def entropy(cls, name: str) -> Type[IEntropy]:
        """
        Retrieve an entropy class by its name.

        :param name: The name of the entropy class.
        :type name: str

        :return: The entropy class corresponding to the given name.
        :rtype: Type[IEntropy]
        """

        if not cls.is_entropy(name=name):
            raise EntropyError(
                "Invalid entropy name", expected=cls.names(), got=name
            )
        return cls.dictionary[name]

    @classmethod
    def is_entropy(cls, name: str) -> bool:
        """
        Check if a given name is a valid entropy name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is valid, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


__all__: List[str] = [
    "IEntropy",
    "ALGORAND_ENTROPY_STRENGTHS",
    "BIP39_ENTROPY_STRENGTHS",
    "SLIP39_ENTROPY_STRENGTHS",
    "ELECTRUM_V1_ENTROPY_STRENGTHS",
    "ELECTRUM_V2_ENTROPY_STRENGTHS",
    "MONERO_ENTROPY_STRENGTHS",
    "ENTROPIES"
] + [
    cls.__name__ for cls in ENTROPIES.classes()
]
