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
from ..addresses import P2WPKHAddress
from ..exceptions import DerivationError
from ..derivations import (
    IDerivation, BIP84Derivation, CustomDerivation
)
from .bip44 import BIP44HD


class BIP84HD(BIP44HD):

    _derivation: Union[BIP84Derivation, CustomDerivation]

    def __init__(
        self, ecc: Type[IEllipticCurveCryptography], public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED, **kwargs
    ) -> None:
        """
        Initializes a new instance of the BIP84HD class.

        :param ecc: The elliptic curve cryptography implementation.
        :type ecc: Type[IEllipticCurveCryptography]
        :param public_key_type: The type of public key (compressed or uncompressed), defaults to compressed.
        :type public_key_type: str

        :param kwargs: Additional parameters to configure the BIP84 derivation path, such as coin_type, account, change, and address.
        :type kwargs: dict
        """

        super(BIP84HD, self).__init__(ecc=ecc, public_key_type=public_key_type, **kwargs)

        self._derivation = BIP84Derivation(
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
        return "BIP84"

    def from_derivation(self, derivation: IDerivation) -> "BIP84HD":
        """
        Updates the current instance with a new derivation path.

        :param derivation: The new derivation path instance.
        :type derivation: IDerivation

        :return: The updated BIP84HD instance.
        :rtype: BIP84HD
        """

        if not isinstance(derivation, (BIP84Derivation, CustomDerivation)):
            raise DerivationError(
                "Invalid derivation instance", expected=(BIP84Derivation, CustomDerivation), got=type(derivation)
            )

        self.clean_derivation()
        self._derivation = derivation
        for index in self._derivation.indexes():
            self.drive(index)
        return self

    def root_xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Returns the root extended private key (xprv).

        :param version: The version of the xprv key, either as bytes or an integer. Defaults to P2WPKH xprv version.
        :type version: Union[bytes, int]
        :param encoded: Whether the key should be encoded or not. Defaults to True.
        :type encoded: bool

        :return: The root extended private key as a string, or None if the key cannot be generated.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).root_xprivate_key(version=version, encoded=encoded)

    def root_xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Returns the root extended public key (xpub).

        :param version: The version of the xpub key, either as bytes or an integer. Defaults to P2WPKH xpub version.
        :type version: Union[bytes, int]
        :param encoded: Whether the key should be encoded or not. Defaults to True.
        :type encoded: bool

        :return: The root extended public key as a string, or None if the key cannot be generated.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).root_xpublic_key(version=version, encoded=encoded)

    def xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Returns the extended private key (xprv).

        :param version: The version of the xprv key, either as bytes or an integer. Defaults to P2WPKH xprv version.
        :type version: Union[bytes, int]
        :param encoded: Whether the key should be encoded or not. Defaults to True.
        :type encoded: bool

        :return: The extended private key as a string, or None if the key cannot be generated.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).xprivate_key(version=version, encoded=encoded)

    def xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Returns the extended public key (xpub).

        :param version: The version of the xpub key, either as bytes or an integer. Defaults to P2WPKH xpub version.
        :type version: Union[bytes, int]
        :param encoded: Whether the key should be encoded or not. Defaults to True.
        :type encoded: bool

        :return: The extended public key as a string, or None if the key cannot be generated.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).xpublic_key(version=version, encoded=encoded)

    def address(
        self,
        hrp: str = Bitcoin.NETWORKS.MAINNET.HRP,
        witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH,
        **kwargs
    ) -> str:
        """
        Generates a native SegWit (P2WPKH) address.

        :param hrp: The Human-readable Part (HRP) for the address. Defaults to Bitcoin's mainnet HRP.
        :type hrp: str
        :param witness_version: The witness version for the address. Defaults to P2WPKH witness version.
        :type witness_version: int
        :param kwargs: Additional keyword arguments, not used in this method.

        :return: The generated native SegWit (P2WPKH) address.
        :rtype: str
        """

        return P2WPKHAddress.encode(
            public_key=self._public_key,
            hrp=hrp,
            witness_version=witness_version,
            public_key_type=self._public_key_type
        )
