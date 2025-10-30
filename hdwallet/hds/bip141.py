#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Type, Union, Optional
)

from ..cryptocurrencies import Bitcoin
from ..eccs import IEllipticCurveCryptography
from ..consts import (
    PUBLIC_KEY_TYPES, SEMANTICS
)
from ..addresses import (
    P2WPKHAddress, P2WPKHInP2SHAddress, P2WSHAddress, P2WSHInP2SHAddress
)
from ..exceptions import (
    Error, AddressError
)
from .bip32 import BIP32HD


class BIP141HD(BIP32HD):

    _address: str
    _xprivate_key_version: Union[bytes, int]
    _xpublic_key_version: Union[bytes, int]
    _semantic: str

    def __init__(
        self,
        ecc: Type[IEllipticCurveCryptography],
        semantic: str,
        public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED,
        **kwargs
    ) -> None:
        """
        Initialize a BIP141HD instance with elliptic curve cryptography, semantic information,
        public key type, and optional keyword arguments.

        :param ecc: Elliptic curve cryptography class or type.
        :type ecc: Type[IEllipticCurveCryptography]
        :param semantic: Semantic information to initialize from.
        :type semantic: str
        :param public_key_type: Type of public key (default is PUBLIC_KEY_TYPES.COMPRESSED).
        :type public_key_type: str

        :param kwargs: Additional keyword arguments for initialization.
        """

        super(BIP141HD, self).__init__(ecc=ecc, public_key_type=public_key_type, **kwargs)

        self.from_semantic(semantic=semantic, **kwargs)

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the bip class.

        :return: The name of the bip class.
        :rtype: str
        """
        return "BIP141"

    def from_semantic(self, semantic: str, **kwargs) -> "BIP141HD":
        """
        Initialize the BIP141HD instance based on the provided semantic type.

        :param semantic: Semantic type for address generation.
        :type semantic: str
        :param kwargs: Additional keyword arguments for specific semantic types.

        :return: Self-reference for method chaining.
        :rtype: BIP141HD
        """

        if semantic not in SEMANTICS.get_types():
            raise Error(
                f"Invalid {self.name()} semantic type", expected=SEMANTICS.get_types(), got=semantic
            )
        self._semantic = semantic

        if semantic == SEMANTICS.P2WPKH:
            self._address = P2WPKHAddress.name()
            self._xprivate_key_version = kwargs.get(
                "p2wpkh_xprivate_key_version", Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH
            )
            self._xpublic_key_version = kwargs.get(
                "p2wpkh_xpublic_key_version", Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH
            )
        elif semantic == SEMANTICS.P2WPKH_IN_P2SH:
            self._address = P2WPKHInP2SHAddress.name()
            self._xprivate_key_version = kwargs.get(
                "p2wpkh_in_p2sh_xprivate_key_version", Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WPKH_IN_P2SH
            )
            self._xpublic_key_version = kwargs.get(
                "p2wpkh_in_p2sh_xpublic_key_version", Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WPKH_IN_P2SH
            )
        elif semantic == SEMANTICS.P2WSH:
            self._address = P2WSHAddress.name()
            self._xprivate_key_version = kwargs.get(
                "p2wsh_xprivate_key_version", Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WSH
            )
            self._xpublic_key_version = kwargs.get(
                "p2wsh_xpublic_key_version", Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WSH
            )
        elif semantic == SEMANTICS.P2WSH_IN_P2SH:
            self._address = P2WSHInP2SHAddress.name()
            self._xprivate_key_version = kwargs.get(
                "p2wsh_in_p2sh_xprivate_key_version", Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2WSH_IN_P2SH
            )
            self._xpublic_key_version = kwargs.get(
                "p2wsh_in_p2sh_xpublic_key_version", Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2WSH_IN_P2SH
            )
        return self

    def semantic(self) -> str:
        """
        Retrieve the semantic type associated with this BIP141HD instance.

        :return: Semantic type.
        :rtype: str
        """
        return self._semantic

    def root_xprivate_key(
        self, version: Optional[Union[bytes, int]] = None, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the root extended private key for the BIP141HD instance.

        :param version: Optional version bytes or integer for the extended private key.
                        If None, uses the instance's `_xprivate_key_version`.
        :type version: Union[bytes, int], optional
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: Root extended private key as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP141HD, self).root_xprivate_key(
            version=(self._xprivate_key_version if version is None else version), encoded=encoded
        )

    def root_xpublic_key(
        self, version: Optional[Union[bytes, int]] = None, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the root extended public key for the BIP141HD instance.

        :param version: Optional version bytes or integer for the extended public key.
                        If None, uses the instance's `_xpublic_key_version`.
        :type version: Union[bytes, int], optional
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: Root extended public key as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP141HD, self).root_xpublic_key(
            version=(self._xpublic_key_version if version is None else version), encoded=encoded
        )

    def xprivate_key(
        self, version: Optional[Union[bytes, int]] = None, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the extended private key for the BIP141HD instance.

        :param version: Optional version bytes or integer for the extended private key.
                        If None, uses the instance's `_xprivate_key_version`.
        :type version: Union[bytes, int], optional
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: Extended private key as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP141HD, self).xprivate_key(
            version=(self._xprivate_key_version if version is None else version), encoded=encoded
        )

    def xpublic_key(
        self, version: Optional[Union[bytes, int]] = None, encoded: bool = True
    ) -> Optional[str]:
        """
        Generate the extended public key for the BIP141HD instance.

        :param version: Optional version bytes or integer for the extended public key.
                        If None, uses the instance's `_xpublic_key_version`.
        :type version: Union[bytes, int], optional
        :param encoded: Flag indicating whether the key should be encoded (default is True).
        :type encoded: bool

        :return: Extended public key as a string, or None if not available.
        :rtype: Optional[str]
        """

        return super(BIP141HD, self).xpublic_key(
            version=(self._xpublic_key_version if version is None else version), encoded=encoded
        )

    def address(
        self,
        address: Optional[str] = None,
        script_address_prefix: int = Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
        hrp: str = Bitcoin.NETWORKS.MAINNET.HRP,
        witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH,
        **kwargs
    ) -> str:
        """
        Generate an address based on the specified address type for the BIP141HD instance.

        :param address: Optional address type to encode. If None, uses the instance's `_address`.
        :type address: Optional[str]

        :param script_address_prefix: Script address prefix for P2WPKH-in-P2SH and P2WSH-in-P2SH addresses.
                                      Default is Bitcoin mainnet script address prefix.
        :type script_address_prefix: int
        :param hrp: Human-readable part for P2WPKH and P2WSH addresses. Default is Bitcoin mainnet HRP.
        :type hrp: str
        :param witness_version: Witness version for P2WPKH and P2WSH addresses. Default is Bitcoin mainnet witness version.
        :type witness_version: int

        :return: Encoded address string.
        :rtype: str
        """

        if address is None:
            address = self._address
        if address == P2WPKHAddress.name():
            return P2WPKHAddress.encode(
                public_key=self._public_key,
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        elif address == P2WPKHInP2SHAddress.name():
            return P2WPKHInP2SHAddress.encode(
                public_key=self._public_key,
                script_address_prefix=script_address_prefix,
                public_key_type=self._public_key_type
            )
        elif address == P2WSHAddress.name():
            return P2WSHAddress.encode(
                public_key=self._public_key,
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        elif address == P2WSHInP2SHAddress.name():
            return P2WSHInP2SHAddress.encode(
                public_key=self._public_key,
                script_address_prefix=script_address_prefix,
                public_key_type=self._public_key_type
            )
        raise AddressError(
            f"Invalid {self.name()} address",
            expected=[
                P2WPKHAddress.name(),
                P2WPKHInP2SHAddress.name(),
                P2WSHAddress.name(),
                P2WSHInP2SHAddress.name()
            ],
            got=self._address
        )
