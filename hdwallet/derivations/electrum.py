#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Tuple
)

from ..utils import (
    normalize_index, normalize_derivation, index_tuple_to_string
)
from .iderivation import IDerivation


class ElectrumDerivation(IDerivation):
    """
    This class implements the Electrum standard for hierarchical deterministic wallets.
    Electrum defines a specific path structure for deriving keys from a master seed.

    .. note::
        This class inherits from the ``IDerivation`` class, thereby ensuring that all functions are accessible.
    """

    _change: Union[Tuple[int, bool], Tuple[int, int, bool]]
    _address: Union[Tuple[int, bool], Tuple[int, int, bool]]

    def __init__(
        self, change: Union[str, int, Tuple[int, int]] = 0, address: Union[str, int, Tuple[int, int]] = 0
    ) -> None:
        """
        Initialize an ElectrumDerivation object with the given change and address indexes.

        :param change: The change index, which can be a string, integer, or tuple.
                       Default is 0.
        :type change: Union[str, int, Tuple[int, int]]
        :param address: The address index, which can be a string, integer, or tuple.
                        Default is 0.
        :type address: Union[str, int, Tuple[int, int]]

        :return: No return
        :rtype: NoneType
        """

        super(ElectrumDerivation, self).__init__()

        self._change = normalize_index(index=change, hardened=False)
        self._address = normalize_index(index=address, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._change)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the derivation class.

        :return: The name of the derivation class.
        :rtype: str
        """

        return "Electrum"

    def from_change(self, change: Union[str, int, Tuple[int, int]]) -> "ElectrumDerivation":
        """
        Sets the change index and updates the derivation path accordingly.

        :param change: The change index to set. It can be a string, integer, or tuple representing the index.
        :type change: Union[str, int, Tuple[int, int]]

        :return: The instance of ElectrumDerivation with the updated change index.
        :rtype: ElectrumDerivation
        """

        self._change = normalize_index(index=change, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._change)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def from_address(self, address: Union[str, int, Tuple[int, int]]) -> "ElectrumDerivation":
        """
        Sets the address index and updates the derivation path accordingly.

        :param address: The address index to set. It can be a string, integer, or tuple representing the index.
        :type address: Union[str, int, Tuple[int, int]]

        :return: The instance of ElectrumDerivation with the updated address index.
        :rtype: ElectrumDerivation
        """

        self._address = normalize_index(index=address, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._change)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def clean(self) -> "ElectrumDerivation":
        """
        Resets the derivation to the default state with change and address indices set to 0.

        :return: The instance of ElectrumDerivation after resetting to default state.
        :rtype: ElectrumDerivation
        """

        self._change = normalize_index(index=0, hardened=False)
        self._address = normalize_index(index=0, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._change)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def change(self) -> int:
        """
        Retrieves the change index from the internal `_change` attribute.

        :return: The change index.
        :rtype: int
        """

        return (
            self._change[1] if len(self._change) == 3 else self._change[0]
        )

    def address(self) -> int:
        """
        Retrieves the address index from the internal `_address` attribute.

        :return: The address index.
        :rtype: int
        """

        return (
            self._address[1] if len(self._address) == 3 else self._address[0]
        )
