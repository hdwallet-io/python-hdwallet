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
from ..addresses import P2WPKHInP2SHAddress
from ..exceptions import DerivationError
from ..derivations import (
    IDerivation, BIP49Derivation, CustomDerivation
)
from .bip44 import BIP44HD


class BIP49HD(BIP44HD):

    _derivation: Union[BIP49Derivation, CustomDerivation]

    def __init__(
        self, ecc: Type[IEllipticCurveCryptography], public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED, **kwargs
    ) -> None:
        """
        Initializes a BIP49HD object.

        :param ecc: Elliptic curve cryptography implementation.
        :type ecc: Type[IEllipticCurveCryptography]
        :param public_key_type: Type of public key to use (default: COMPRESSED).
        :type public_key_type: str

        :param kwargs: Additional keyword arguments for initialization.
        """

        super(BIP49HD, self).__init__(ecc=ecc, public_key_type=public_key_type, **kwargs)

        self._derivation = BIP49Derivation(
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
        return "BIP49"

    def from_derivation(self, derivation: IDerivation) -> "BIP49HD":
        """
        Sets the derivation path for the BIP49HD instance from a given derivation object.

        :param derivation: The derivation object to set.
        :type derivation: IDerivation

        :return: The updated BIP49HD instance.
        :rtype: BIP49HD
        """

        if not isinstance(derivation, (BIP49Derivation, CustomDerivation)):
            raise DerivationError(
                "Invalid derivation instance", expected=(BIP49Derivation, CustomDerivation), got=type(derivation)
            )

        self.clean_derivation()
        self._derivation = derivation
        for index in self._derivation.indexes():
            self.drive(index)
        return self

    def root_xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH_IN_P2SH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the root extended private key (xprivate key) for the BIP44HD instance.

        :param version: The version bytes or integer for the xprivate key.
        :type version: Union[bytes, int]
        :param encoded: Whether to encode the xprivate key or return it in raw form, defaults to True.
        :type encoded: bool

        :return: The root extended private key (xprivate key) if available, otherwise None.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).root_xprivate_key(version=version, encoded=encoded)

    def root_xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH_IN_P2SH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the root extended public key (xpublic key) for the BIP44HD instance.

        :param version: The version bytes or integer for the xpublic key.
        :type version: Union[bytes, int]
        :param encoded: Whether to encode the xpublic key or return it in raw form, defaults to True.
        :type encoded: bool

        :return: The root extended public key (xpublic key) if available, otherwise None.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).root_xpublic_key(version=version, encoded=encoded)

    def xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH_IN_P2SH, encoded: bool = True
    ) -> Optional[str]:
        """
            Generates the extended private key (xprivate key) for the BIP44HD instance.

            :param version: The version bytes or integer for the xprivate key.
            :type version: Union[bytes, int]
            :param encoded: Whether to encode the xprivate key or return it in raw form, defaults to True.
            :type encoded: bool

            :return: The extended private key (xprivate key) if available, otherwise None.
            :rtype: Optional[str]
            """

        return super(BIP44HD, self).xprivate_key(version=version, encoded=encoded)

    def xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH_IN_P2SH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the extended public key (xpublic key) for the BIP44HD instance.

        :param version: The version bytes or integer for the xpublic key.
        :type version: Union[bytes, int]
        :param encoded: Whether to encode the xpublic key or return it in raw form, defaults to True.
        :type encoded: bool

        :return: The extended public key (xpublic key) if available, otherwise None.
        :rtype: Optional[str]
        """

        return super(BIP44HD, self).xpublic_key(version=version, encoded=encoded)

    def address(
        self, script_address_prefix: int = Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX, **kwargs
    ) -> str:
        """
        Generates the P2WPKH-in-P2SH address for the BIP49HD instance.

        :param script_address_prefix: The script address prefix for encoding the address, defaults to the main network prefix.
        :type script_address_prefix: int

        :return: The P2WPKH-in-P2SH encoded address.
        :rtype: str
        """

        return P2WPKHInP2SHAddress.encode(
            public_key=self._public_key,
            script_address_prefix=script_address_prefix,
            public_key_type=self._public_key_type
        )
