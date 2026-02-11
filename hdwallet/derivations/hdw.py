#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Tuple, Union, Optional, Type
)

from ..eccs import (
    IEllipticCurveCryptography,
    SLIP10Secp256k1ECC,
    SLIP10Ed25519ECC,
    SLIP10Nist256p1ECC,
    KholawEd25519ECC,
    SLIP10Ed25519Blake2bECC,
    SLIP10Ed25519MoneroECC
)
from ..utils import (
    normalize_index, normalize_derivation, index_tuple_to_string
)
from ..exceptions import DerivationError
from .iderivation import IDerivation


class HDWDerivation(IDerivation):
    """
    This class implements the HDW standard for hierarchical deterministic wallets.
    HDW defines a specific path structure for deriving keys from a master seed.

    .. note::
        This class inherits from the ``IDerivation`` class, thereby ensuring that all functions are accessible.
    """

    _account: Union[Tuple[int, bool], Tuple[int, int, bool]]
    _ecc: Tuple[int, bool]
    _address: Union[Tuple[int, bool], Tuple[int, int, bool]]

    def __init__(
        self,
        account: Union[str, int, Tuple[int, int]] = 0,
        ecc: Optional[Union[str, int, Type[IEllipticCurveCryptography]]] = SLIP10Secp256k1ECC,
        address: Union[str, int, Tuple[int, int]] = 0
    ) -> None:
        """
        Initialize a HDW derivation path with specified parameters.

        :param account: The HDW account index or tuple. Defaults to 0.
        :type account: Union[str, int, Tuple[int, int]]
        :param ecc: The HDW ecc index.
        :type ecc: Union[str, int, Type[IEllipticCurveCryptography]]
        :param address: The HDW address index or tuple. Defaults to 0.
        :type address: Union[str, int, Tuple[int, int]]

        :return: None
        """
        super(HDWDerivation, self).__init__()

        self._account = normalize_index(index=account, hardened=True)
        self._ecc = normalize_index(
            index=self.get_ecc_value(ecc=ecc, name_only=False), hardened=False
        )
        self._address = normalize_index(index=address, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/"
            f"{index_tuple_to_string(index=self._account)}/"
            f"{index_tuple_to_string(index=self._ecc)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the derivation class.

        :return: The name of the derivation class.
        :rtype: str
        """

        return "HDW"

    def get_ecc_value(
        self, ecc: Union[str, int, Type[IEllipticCurveCryptography]], name_only: bool = False
    ):

        if isinstance(ecc, IEllipticCurveCryptography):
            curve = ecc.NAME
        elif isinstance(ecc, type) and issubclass(ecc, IEllipticCurveCryptography):
            curve = ecc.NAME
        else:
            curve = ecc

        slip10_secp256k1 = [SLIP10Secp256k1ECC.NAME, 0, '0']
        slip10_ed25519 = [SLIP10Ed25519ECC.NAME, 1, '1']
        slip10_nist256p1 = [SLIP10Nist256p1ECC.NAME, 2, '2']
        kholaw_ed25519 = [KholawEd25519ECC.NAME, 3, '3']
        slip10_ed25519_blake2b = [SLIP10Ed25519Blake2bECC.NAME, 4, '4']
        slip10_ed25519_monero = [SLIP10Ed25519MoneroECC.NAME, 5, '5']

        expected_ecc = (
            slip10_secp256k1 + slip10_ed25519 + slip10_nist256p1 +
            kholaw_ed25519 + slip10_ed25519_blake2b + slip10_ed25519_monero
        )

        if curve not in expected_ecc:
            raise DerivationError(
                f"Bad {self.name()} ECC index",
                expected=expected_ecc, got=curve
            )

        if curve in slip10_secp256k1:
            return SLIP10Secp256k1ECC.NAME if name_only else 0
        if curve in slip10_ed25519:
            return SLIP10Ed25519ECC.NAME if name_only else 1
        if curve in slip10_nist256p1:
            return SLIP10Nist256p1ECC.NAME if name_only else 2
        if curve in kholaw_ed25519:
            return KholawEd25519ECC.NAME if name_only else 3
        if curve in slip10_ed25519_blake2b:
            return SLIP10Ed25519Blake2bECC.NAME if name_only else 4
        if curve in slip10_ed25519_monero:
            return SLIP10Ed25519MoneroECC.NAME if name_only else 5

    def from_account(self, account: Union[str, int, Tuple[int, int]]) -> "HDWDerivation":
        """
        Set the object's `_account` attribute to the specified account index or tuple,
        updating `_path`, `_indexes`, and `_derivations` accordingly.

        :param account: The account index or tuple to set. Can be a string, integer, or tuple of two integers.
        :type account: Union[str, int, Tuple[int, int]]

        :return: The updated `HDWDerivation` object itself after setting the account.
        :rtype: HDWDerivation
        """

        self._account = normalize_index(index=account, hardened=True)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/"
            f"{index_tuple_to_string(index=self._account)}/"
            f"{index_tuple_to_string(index=self._ecc)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def from_ecc(self, ecc: Union[str, int, Type[IEllipticCurveCryptography]]) -> "HDWDerivation":
        """
        Set the object's `_ecc` attribute to the specified ecc index or key,
        updating `_path`, `_indexes`, and `_derivations` accordingly.

        :param ecc: The ecc index or key to set. Can be a string, integer, or one of the predefined keys.
        :type ecc: Union[str, int, Type[IEllipticCurveCryptography]]

        :return: The updated `HDWDerivation` object itself after setting the ecc.
        :rtype: HDWDerivation
        """

        self._ecc = normalize_index(
            index=self.get_ecc_value(ecc=ecc, name_only=False), hardened=False
        )
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/"
            f"{index_tuple_to_string(index=self._account)}/"
            f"{index_tuple_to_string(index=self._ecc)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def from_address(self, address: Union[str, int, Tuple[int, int]]) -> "HDWDerivation":
        """
        Set the object's `_address` attribute to the specified address index or tuple of indexes,
        updating `_path`, `_indexes`, and `_derivations` accordingly.

        :param address: The address index or tuple of indexes to set. Should be non-hardened.
        :type address: Union[str, int, Tuple[int, int]]

        :return: The updated `HDWDerivation` object itself after setting the address.
        :rtype: HDWDerivation
        """

        self._address = normalize_index(index=address, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/"
            f"{index_tuple_to_string(index=self._account)}/"
            f"{index_tuple_to_string(index=self._ecc)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def clean(self) -> "HDWDerivation":
        """
        Reset the object's attributes related to HDW derivation to their initial states or defaults.

        :return: The updated `HDWDerivation` object itself after cleaning.
        :rtype: HDWDerivation
        """

        self._account = normalize_index(index=0, hardened=True)
        self._address = normalize_index(index=0, hardened=False)
        self._path, self._indexes, self._derivations = normalize_derivation(path=(
            f"m/"
            f"{index_tuple_to_string(index=self._account)}/"
            f"{index_tuple_to_string(index=self._ecc)}/"
            f"{index_tuple_to_string(index=self._address)}"
        ))
        return self

    def account(self) -> int:
        """
        Retrieve the account value from the object's `_account` attribute.

        Checks the length of `_account`. If it equals 3, returns the second
        element; otherwise, returns the first element.

        :return: The account value stored in `_account`.
        :rtype: int
        """

        return (
            self._account[1] if len(self._account) == 3 else self._account[0]
        )

    def ecc(self, name_only: bool = True) -> str:
        """
        Retrieve the ecc value from the object's eccs dictionary.

        Iterates through the `eccs` dictionary, and if a value matches the first element of `_ecc`,
        sets the corresponding key as the ecc value.

        :param name_only: Return the ECC name if True, or its index if False.
        :type name_only: bool
        :return: The key from the `eccs` dictionary that corresponds to the `_ecc` value, or `None` if not found.
        :rtype: str
        """
        return self.get_ecc_value(ecc=self._ecc[0], name_only=name_only)

    def address(self) -> int:
        """
        Retrieve the address from the object.

        :return: The address value.
        :rtype: int
        """

        return (
            self._address[1] if len(self._address) == 3 else self._address[0]
        )
