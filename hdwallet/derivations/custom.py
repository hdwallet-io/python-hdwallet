#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, List
)

from ..utils import normalize_derivation
from ..exceptions import DerivationError
from .iderivation import IDerivation


class CustomDerivation(IDerivation):
    """
    This class implements the Custom standard for hierarchical deterministic wallets.
    Custom defines a specific path structure for deriving keys from a master seed.

    .. note::
        This class inherits from the ``IDerivation`` class, thereby ensuring that all functions are accessible.
    """

    def __init__(
        self, path: Optional[str] = None, indexes: Optional[List[int]] = None
    ) -> None:
        """
        Initialize a CustomDerivation object with the given path and indexes.

        :param path: The derivation path as a string. Default is None.
        :type path: Optional[str]
        :param indexes: A list of indexes for the derivation path. Default is None.
        :type indexes: Optional[List[int]]

        :return: No return
        :rtype: NoneType
        """

        super(CustomDerivation, self).__init__(path, indexes)

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the derivation class.

        :return: The name of the derivation class.
        :rtype: str
        """

        return "Custom"

    def from_path(self, path: str) -> "CustomDerivation":
        """
        Sets the derivation path and indexes list from a given path string.

        :param path: The path string to set the derivation path and indexes list.
                     It should be in the format like "m/0'/0".
        :type path: str

        :return: The instance of CustomDerivation after setting the derivation path and indexes list.
        :rtype: CustomDerivation
        """

        if not isinstance(path, str):
            raise DerivationError("Bad path instance", expected=str, got=type(path))
        elif path[0:2] != "m/":
            raise DerivationError(
                "Bad path format", expected="like this type of path \"m/0'/0\"", got=path
            )

        self._path, self._indexes, self._derivations = normalize_derivation(path=path)
        return self

    def from_indexes(self, indexes: List[int]) -> "CustomDerivation":
        """
        Sets the derivation path and indexes list from a list of indexes.

        :param indexes: The list of indexes to set the derivation path and indexes list.
        :type indexes: List[int]

        :return: The instance of CustomDerivation after setting the derivation path and indexes list.
        :rtype: CustomDerivation
        """

        if not isinstance(indexes, list):
            raise DerivationError("Bad indexes instance", expected=list, got=type(indexes))

        self._path, self._indexes, self._derivations = normalize_derivation(indexes=indexes)
        return self

    def from_index(self, index: int, hardened: bool = False) -> "CustomDerivation":
        """
        Appends an index to the derivation path and indexes list based on whether it's hardened.

        :param index: The index to append to the derivation path and indexes list.
        :type index: int
        :param hardened: Indicates if the index is hardened (True) or not (False), defaults to False.
        :type hardened: bool

        :return: The instance of CustomDerivation after appending the index.
        :rtype: CustomDerivation
        """

        if not isinstance(index, int):
            raise DerivationError("Bad index instance", expected=int, got=type(index))

        self._indexes.append(index + 0x80000000) if hardened else self._indexes.append(index)
        path = f"{index}'" if hardened else f"{index}"
        self.from_path(
            f"{self._path}{path}" if self._path == "m/" else f"{self._path}/{path}"
        )
        return self

    def clean(self) -> "CustomDerivation":
        """
        Resets the derivation path, indexes, and derivations to their default values.

        :return: The instance of CustomDerivation after cleaning.
        :rtype: CustomDerivation
        """

        self._path, self._indexes, self._derivations = normalize_derivation(
            path=None, indexes=None
        )
        return self
