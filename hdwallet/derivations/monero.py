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


class MoneroDerivation(IDerivation):
    """
    This class implements the Monero standard for hierarchical deterministic wallets.
    Monero defines a specific path structure for deriving keys from a master seed.

    .. note::
        This class inherits from the ``IDerivation`` class, thereby ensuring that all functions are accessible.
    """

    _minor: Union[Tuple[int, bool], Tuple[int, int, bool]]
    _major: Union[Tuple[int, bool], Tuple[int, int, bool]]

    def __init__(
        self, minor: Union[str, int, Tuple[int, int]] = 1, major: Union[str, int, Tuple[int, int]] = 0
    ) -> None:
        """
        Initialize a MoneroDerivation instance with the provided minor and major indexes.

        :param minor: The minor index to set. Can be a string, integer, or tuple of integers. Defaults to 1.
        :type minor: Union[str, int, Tuple[int, int]]
        :param major: The major index to set. Can be a string, integer, or tuple of integers. Defaults to 0.
        :type major: Union[str, int, Tuple[int, int]]

        :return: No return
        :rtype: NoneType
        """

        super(MoneroDerivation, self).__init__()

        self._minor = normalize_index(index=minor, hardened=False)
        self._major = normalize_index(index=major, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._minor)}/"
            f"{index_tuple_to_string(index=self._major)}"
        ))

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the derivation class.

        :return: The name of the derivation class.
        :rtype: str
        """

        return "Monero"

    def from_minor(self, minor: Union[str, int, Tuple[int, int]]) -> "MoneroDerivation":
        """
        Sets the minor index for Monero derivation and updates the derivation path accordingly.

        This method accepts a minor index, normalizes it, and updates the derivation path to reflect the new
        minor index value.

        :param minor: The minor index to set. Can be a string, integer, or tuple of integers.
        :type minor: Union[str, int, Tuple[int, int]]

        :return: The instance of MoneroDerivation with the updated minor index.
        :rtype: MoneroDerivation
        """

        self._minor = normalize_index(index=minor, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._minor)}/"
            f"{index_tuple_to_string(index=self._major)}"
        ))
        return self

    def from_major(self, major: Union[str, int, Tuple[int, int]]) -> "MoneroDerivation":
        """
        Sets the major index for Monero derivation and updates the derivation path accordingly.

        This method accepts a major index, normalizes it, and updates the derivation path to reflect the new
        major index value.

        :param major: The major index to set. Can be a string, integer, or tuple of integers.
        :type major: Union[str, int, Tuple[int, int]]

        :return: The instance of MoneroDerivation with the updated major index.
        :rtype: MoneroDerivation
        """

        self._major = normalize_index(index=major, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._minor)}/"
            f"{index_tuple_to_string(index=self._major)}"
        ))
        return self

    def clean(self) -> "MoneroDerivation":
        """
        Resets the derivation path to default values for Monero derivation.

        This method sets the `minor` index to 1 and the `major` index to 0, and updates the derivation path
        accordingly.

        :return: The instance of MoneroDerivation with the reset derivation path.
        :rtype: MoneroDerivation
        """

        self._minor = normalize_index(index=1, hardened=False)
        self._major = normalize_index(index=0, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/{index_tuple_to_string(index=self._minor)}/"
            f"{index_tuple_to_string(index=self._major)}"
        ))
        return self

    def minor(self) -> int:
        """
        Retrieves the minor index from the internal `_minor` attribute.

        :return: The minor index.
        :rtype: int
        """

        return (
            self._minor[1] if len(self._minor) == 3 else self._minor[0]
        )

    def major(self) -> int:
        """
        Retrieves the major index from the internal `_major` attribute.

        :return: The major index.
        :rtype: int
        """

        return (
            self._major[1] if len(self._major) == 3 else self._major[0]
        )
