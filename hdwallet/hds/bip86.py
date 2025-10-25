#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Type, Union, Optional
)

from ..cryptocurrencies import Bitcoin
from ..eccs import IEllipticCurveCryptography
from ..consts import PUBLIC_KEY_TYPES
from ..addresses import P2TRAddress
from ..exceptions import DerivationError
from ..derivations import (
    IDerivation, BIP86Derivation
)
from .bip44 import BIP44HD


class BIP86HD(BIP44HD):

    _derivation: BIP86Derivation

    def __init__(
        self, ecc: Type[IEllipticCurveCryptography], public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED, **kwargs
    ) -> None:
        """
        Initialize a BIP86HD instance.

        :param ecc: The type of elliptic curve cryptography to be used.
        :type ecc: Type[IEllipticCurveCryptography]

        :param public_key_type: The type of public key compression (default: COMPRESSED).
        :type public_key_type: str
        """

        super(BIP86HD, self).__init__(ecc=ecc, public_key_type=public_key_type, **kwargs)

        self._derivation = BIP86Derivation(
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
        return "BIP86"

    def from_derivation(self, derivation: IDerivation) -> "BIP86HD":
        """
        Initialize the BIP86HD instance from a given derivation.

        :param derivation: The derivation object to initialize from.
        :type derivation: IDerivation

        :return: The updated BIP86HD instance.
        :rtype: BIP86HD
        """

        if not isinstance(derivation, BIP86Derivation):
            raise DerivationError(
                "Invalid derivation instance", expected=BIP86Derivation, got=type(derivation)
            )

        self.clean_derivation()
        self._derivation = derivation
        for index in self._derivation.indexes():
            self.drive(index)
        return self

    def root_xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2TR, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the root extended private key (xprv) according to BIP44 for the specified version and encoding.

        :param version: The version bytes or integer for the extended private key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: The root extended private key (xprv) as a string, or None if not available.
        :rtype: Optional[str]
        """
        return super(BIP44HD, self).root_xprivate_key(version=version, encoded=encoded)

    def root_xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2TR, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the root extended public key (xpub) according to BIP44 for the specified version and encoding.

        :param version: The version bytes or integer for the root extended public key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: The root extended public key (xpub) as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).root_xpublic_key(version=version, encoded=encoded)

    def xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2TR, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the extended private key (xprv) according to BIP44 for the specified version and encoding.

        :param version: The version bytes or integer for the extended private key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: The extended private key (xprv) as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).xprivate_key(version=version, encoded=encoded)

    def xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2TR, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the extended public key (xpub) according to BIP44 for the specified version and encoding.

        :param version: The version bytes or integer for the extended public key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: The extended public key (xpub) as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).xpublic_key(version=version, encoded=encoded)

    def address(
        self, hrp: str = Bitcoin.NETWORKS.MAINNET.HRP,
        witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR, **kwargs
    ) -> str:
        """
        Generate a SegWit (P2TR) address using the specified human-readable part (HRP) and witness version.

        :param hrp: Human-readable part for the address encoding (default is Bitcoin.NETWORKS.MAINNET.HRP).
        :type hrp: str

        :param witness_version: Witness version for SegWit address encoding (default is Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR).
        :type witness_version: int
        :param kwargs: Additional keyword arguments passed to the address encoding function.

        :return: The encoded SegWit (P2TR) address as a string.
        :rtype: str
        """

        return P2TRAddress.encode(
            public_key=self._public_key,
            hrp=hrp,
            witness_version=witness_version,
            public_key_type=self._public_key_type
        )
