#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, List, Tuple, Union
)

from ..utils import normalize_derivation


class IDerivation:

    _path: str = "m/"
    _indexes: List[int] = []
    _derivations: List[Tuple[int, bool]] = { }

    def __init__(
        self, path: Optional[str] = None, indexes: Optional[List[int]] = None, **kwargs
    ) -> None:
        """
        Initializes an object for iderivation.  Derived classes may support different
        arguments, but should always support path and indexes.

        :param path: Optional derivation path string.
        :type path: Optional[str]
        :param indexes: Optional list of derivation indexes.
        :type indexes: Optional[List[int]]

        :return: No return
        :rtype: NoneType
        """

        self._path, self._indexes, self._derivations = normalize_derivation(
            path=path, indexes=indexes
        )

    def __str__(self) -> str:
        """
        Return the string representation of the derivation path.

        :return: The derivation path as a string.
        :rtype: str
        """

        return self._path

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the derivation class.

        :return: The name of the derivation class.
        :rtype: str
        """

        pass

    def clean(self) -> "IDerivation":
        """
        Reset the object's attributes to their initial states or defaults.

        :return: The updated `IDerivation` object itself after cleaning.
        :rtype: IDerivation
        """

        pass

    def path(self) -> str:
        """
        Retrieves the path associated with the current instance.

        :return: The derivation as a string.
        :rtype: str
        """

        return self._path

    def indexes(self) -> List[int]:
        """
        Retrieve the list of indexes in the derivation path.

        :return: A list of integer indexes used in the derivation path.
        :rtype: List[int]
        """

        return self._indexes

    def derivations(self) -> List[Tuple[int, bool]]:
        """
        Retrieve the list of derivations in the derivation path.

        :return: A list of tuples where each tuple contains an index and a boolean indicating whether the index is hardened.
        :rtype: List[Tuple[int, bool]]
        """

        return self._derivations

    def depth(self) -> int:
        """
        Retrieve the depth of the derivation path.

        :return: The number of derivation levels in the path.
        :rtype: int
        """

        return len(self._derivations)

    def purpose(self) -> int:
        """
        Retrieve the purpose value from the object's `_purpose` attribute.

        This method returns the first element of the `_purpose` attribute,
        which is assumed to be a list or similar iterable containing integers.

        :return: The purpose value stored as the first element of `_purpose`.
        :rtype: int
        """

        pass

    def coin_type(self) -> int:
        """
        Retrieve the coin type value from the object's `_coin_type` attribute.

        This method returns the value of the `_coin_type` attribute,
        which is expected to be an integer representing the type of coin.

        :return: The coin type value stored in `_coin_type`.
        :rtype: int
        """

        pass

    def account(self) -> int:
        """
        Retrieve the account value from the object's `_account` attribute.

        This method returns the value of the `_account` attribute,
        which is expected to be an integer representing the account identifier.

        :return: The account value stored in `_account`.
        :rtype: int
        """

        pass

    def change(self) -> Union[int, str]:
        """
        Retrieve the change value from the object's `_change` attribute.

        This method returns the value of the `_change` attribute,
        which can be an integer or a string, representing the change status or type.

        :return: The change value stored in `_change`.
        :rtype: Union[int, str]
        """

        pass

    def role(self) -> str:
        """
        Retrieve the role value from the object's `_role` attribute.

        This method returns the value of the `_role` attribute,
        which is expected to be a string representing the role of the object.

        :return: The role value stored in `_role`.
        :rtype: str
        """

        pass

    def address(self) -> int:
        """
        Retrieve the address value from the object's `_address` attribute.

        This method returns the value of the `_address` attribute,
        which is expected to be an integer representing the address.

        :return: The address value stored in `_address`.
        :rtype: int
        """

        pass

    def minor(self) -> int:
        """
        Retrieve the minor version value from the object's `_minor` attribute.

        This method returns the value of the `_minor` attribute,
        which is expected to be an integer representing the minor version number.

        :return: The minor version value stored in `_minor`.
        :rtype: int
        """

        pass

    def major(self) -> int:
        """
        Retrieve the major version value from the object's `_major` attribute.

        This method returns the value of the `_major` attribute,
        which is expected to be an integer representing the major version number.

        :return: The major version value stored in `_major`.
        :rtype: int
        """

        pass
