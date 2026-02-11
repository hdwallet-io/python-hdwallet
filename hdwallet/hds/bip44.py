#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Tuple, Type
)

from ..cryptocurrencies import Bitcoin
from ..eccs import IEllipticCurveCryptography
from ..consts import PUBLIC_KEY_TYPES
from ..addresses import P2PKHAddress
from ..exceptions import DerivationError
from ..derivations import (
    IDerivation, BIP44Derivation, CustomDerivation
)
from .bip32 import BIP32HD


class BIP44HD(BIP32HD):

    _derivation: Union[BIP44Derivation, CustomDerivation]

    def __init__(
        self, ecc: Type[IEllipticCurveCryptography], public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED, **kwargs
    ) -> None:
        """
        Initialize a BIP44HD object.

        :param ecc: Elliptic curve cryptography class implementing IEllipticCurveCryptography.
        :type ecc: Type[IEllipticCurveCryptography]
        :param public_key_type: Type of public key encoding (compressed or uncompressed), defaults to ``PUBLIC_KEY_TYPES.COMPRESSED``.
        :type public_key_type: str, optional
        :param kwargs: Additional keyword arguments for initialization.
            - coin_type: Integer specifying the coin type, defaults to 0.
            - account: Integer specifying the account index, defaults to 0.
            - change: String specifying the change type ("external-chain" or "internal-chain"), defaults to ``external-chain``.
            - address: Integer specifying the address index, defaults to 0.
        """

        super(BIP44HD, self).__init__(ecc=ecc, public_key_type=public_key_type, **kwargs)

        self._derivation = BIP44Derivation(
            coin_type=kwargs.get("coin_type", 0),
            account=kwargs.get("account", 0),
            change=kwargs.get("change", "external-chain"),
            address=kwargs.get("address", 0)
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the bip class.

        :return: The name of the bip class.
        :rtype: str
        """
        return "BIP44"

    def __update__(self) -> "BIP44HD":
        """
        Update the BIP44HD object based on its current derivation path.

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        self.from_derivation(derivation=self._derivation)
        return self

    def from_coin_type(self, coin_type: int) -> "BIP44HD":
        """
        Update the BIP44HD object's derivation path based on the given coin type.

        :param coin_type: The coin type index.
        :type coin_type: int

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        self._derivation.from_coin_type(coin_type=coin_type)
        self.__update__()
        return self

    def from_account(self, account: Union[int, Tuple[int, int]]) -> "BIP44HD":
        """
        Update the BIP44HD object's derivation path based on the given account.

        :param account: The account index or a tuple of (account index, change).
        :type account: Union[int, Tuple[int, int]]

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        self._derivation.from_account(account=account)
        self.__update__()
        return self

    def from_change(self, change: str) -> "BIP44HD":
        """
        Update the BIP44HD object's derivation path based on the given change type.

        :param change: The change type ('external-chain' or 'internal-chain').
        :type change: str

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        self._derivation.from_change(change=change)
        self.__update__()
        return self

    def from_address(self, address: Union[int, Tuple[int, int]]) -> "BIP44HD":
        """
        Update the BIP44HD object's derivation path based on the given address index or tuple.

        :param address: The address index (int) or tuple of (account index, address index).
        :type address: Union[int, Tuple[int, int]]

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        self._derivation.from_address(address=address)
        self.__update__()
        return self

    def from_derivation(self, derivation: IDerivation) -> "BIP44HD":
        """
        Initialize the BIP44HD object from a given derivation.

        :param derivation: The BIP44-compatible derivation object.
        :type derivation: IDerivation

        :return: Updated BIP44HD object.
        :rtype: BIP44HD
        """

        if not isinstance(derivation, (BIP44Derivation, CustomDerivation)):
            raise DerivationError(
                "Invalid derivation instance", expected={BIP44Derivation, CustomDerivation}, got=type(derivation)
            )

        self.clean_derivation()
        self._derivation = derivation
        for index in self._derivation.indexes():
            self.drive(index)
        return self

    def address(
        self, public_key_address_prefix: int = Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX, **kwargs
    ) -> str:
        """
        Generates a Bitcoin address using the P2PKHAddress encoding scheme.

        :param public_key_address_prefix: Public key address prefix value for Bitcoin network.
        :type public_key_address_prefix: int
        :param kwargs: Additional keyword arguments for encoding.

        :return: Bitcoin address encoded in P2PKH format.
        :rtype: str
        """

        return P2PKHAddress.encode(
            public_key=self._public_key,
            public_key_address_prefix=public_key_address_prefix,
            public_key_type=self._public_key_type
        )
