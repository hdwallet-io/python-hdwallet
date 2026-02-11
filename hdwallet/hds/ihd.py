#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, List, Optional
)

from ..eccs import IEllipticCurveCryptography
from ..derivations import IDerivation


class IHD:

    _ecc: IEllipticCurveCryptography
    _derivation: IDerivation

    def __init__(self, **kwargs) -> None:
        self._ecc = kwargs.get("ecc")

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the hd class.

        :return: The name of the hd class.
        :rtype: str
        """

    def from_seed(self, seed: Union[bytes, str], **kwargs) -> "IHD":
        """
        Initializes the HD instance from the given seed.

        :param seed: The seed to initialize the instance. It can be of type `bytes`, `str`, or `ISeed`.
        :type seed: Union[bytes, str]
        :param kwargs: Additional keyword arguments.

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_xprivate_key(
        self, xprivate_key: str, encoded: bool = True, strict: bool = False
    ) -> "IHD":
        """
        Initializes the HD instance from the given extended private key (xprivate key).

        :param xprivate_key: The extended private key to initialize the instance.
        :type xprivate_key: str
        :param encoded: Indicates if the xprivate key is encoded. Defaults to True.
        :type encoded: bool
        :param strict: If set to True, enforces strict checking to ensure the xprivate key is a root key. Defaults to False.
        :type strict: bool

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_xpublic_key(
        self, xpublic_key: str, encoded: bool = True, strict: bool = False
    ) -> "IHD":
        """
        Initializes the HD instance from the given extended public key (xpublic key).

        :param xpublic_key: The extended public key to initialize the instance.
        :type xpublic_key: str
        :param encoded: Indicates if the xpublic key is encoded. Defaults to True.
        :type encoded: bool
        :param strict: If set to True, enforces strict checking to ensure the xpublic key is a root key. Defaults to False.
        :type strict: bool

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_wif(self, wif: str) -> "IHD":
        """
        Initializes the HD instance from the given Wallet Import Format (WIF) key.

        :param wif: The Wallet Import Format (WIF) key to initialize the instance.
        :type wif: str

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_private_key(self, private_key: str) -> "IHD":
        """
        Initializes the HD instance from the given private key.

        :param private_key: The private key to initialize the instance, represented as a string.
        :type private_key: str

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_spend_private_key(self, spend_private_key: str) -> "IHD":
        """
        Initialize the HD instance from a spend private key.

        :param spend_private_key: Spend private key to initialize from.
        :type spend_private_key: str

        :return: Updated HD instance initialized from the spend private key.
        :rtype: HD
        """

    def from_public_key(self, public_key: str) -> "IHD":
        """
        Initializes the HD instance from the given public key.

        :param public_key: The public key to initialize the instance, represented as a string.
        :type public_key: str

        :return: The initialized HD instance.
        :rtype: HD
        """

    def from_watch_only(self, view_private_key, spend_public_key) -> "IHD":
        """
        Initialize the MoneroHD instance from watch-only keys.

        :param view_private_key: View private key or seed to initialize from.
        :param spend_public_key: Spend public key to initialize from.

        :return: Updated HD instance initialized from the watch-only keys.
        :rtype: MoneroHD
        """

    def from_derivation(self, derivation: IDerivation) -> "IHD":
        """
        Initializes the MoneroHD instance using the specified derivation path.

        :param derivation: The derivation path to initialize the instance.
                           It must be an instance of `IDerivation`.
        :type derivation: IDerivation

        :return: The initialized MoneroHD instance.
        :rtype: MoneroHD
        """

    def update_derivation(self, derivation: IDerivation) -> "IHD":
        """
        Updates the derivation path for the HD instance.

        This method first cleans the current derivation path and then sets the new
        derivation path provided. It drives the instance through the new derivation path.

        :param derivation: The new derivation path to set. It must be an instance of `IDerivation`.
        :type derivation: IDerivation

        :return: The updated HD instance.
        :rtype: HD
        """

    def clean_derivation(self) -> "IHD":
        """
        Cleans the derivation path of the HD instance.

        :return: The cleaned HD instance.
        :rtype: HD
        """

    def derivation(self) -> IDerivation:
        """
        Retrieves the derivation method used for key generation.

        :return: An object representing the derivation details.
        :rtype: IDerivation
        """
        return self._derivation

    def seed(self) -> Optional[str]:
        """
        Retrieves the seed value as a string if it exists.

        :return: The seed value as a string, or None if the seed is not set.
        :rtype: Optional[str]
        """

    def semantic(self) -> Optional[str]:
        """
        Retrieves the semantic value as a string if it exists.

        :return: The semantic value as a string, or None if the semantic is not set.
        :rtype: Optional[str]
        """

        return None

    def root_xprivate_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the root extended private key (xprv) in serialized format.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root extended private key (xprv) in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

    def root_xpublic_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the root extended public key (xpub) in serialized format.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root extended public key (xpub) in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

    def master_xprivate_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the master extended private key in serialized format.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root extended private key in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

        return self.root_xprivate_key(args, kwargs)

    def master_xpublic_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the master extended public key in serialized format.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The master extended public key in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

        return self.root_xpublic_key(args, kwargs)

    def root_private_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the root private key as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root private key as a hexadecimal string, or None if not set.
        :rtype: Optional[str]
        """

    def root_wif(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the root private key in WIF format.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root private key in WIF format as a string, or None if the root private key is not set.
        :rtype: Optional[str]
        """

    def root_chain_code(self) -> Optional[str]:
        """
        Retrieves the root chain code as a string.

        :return: The root chain code as a string, or None if the root chain code is not set.
        :rtype: Optional[str]
        """

    def root_public_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the root public key as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The root public key as a string, or None if the root public key is not set.
        :rtype: Optional[str]
        """

    def master_private_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the master private key as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The master private key as a string, or None if the master private key is not set.
        :rtype: Optional[str]
        """

    def master_wif(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the master wif as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The master wif as a string, or None if the master private is not set.
        :rtype: Optional[str]
        """

    def master_chain_code(self) -> Optional[str]:
        """
        Retrieves the master chain code as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The master chain code as a string, or None if the master chain code is not set.
        :rtype: Optional[str]
        """

        return self.root_chain_code()

    def master_public_key(self, *args, **kwargs) -> str:
        """
        Retrieves the master public key as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The master public key as a string, or None if the master public key is not set.
        :rtype: Optional[str]
        """

    def xprivate_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the extended private key (xprivate key) as a serialized string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The serialized xprivate key as a string, or None if the private key or chain code is not set.
        :rtype: Optional[str]
        """

    def xpublic_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the extended public key (xpublic key) as a serialized string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The serialized xpublic key as a string, or None if the chain code is not set.
        :rtype: Optional[str]
        """

    def private_key(self, *args, **kwargs) -> Optional[str]:
        """
        Retrieves the private key as a string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The private key as a string, or None if the private key is not set.
        :rtype: Optional[str]
        """

    def spend_private_key(self) -> str:
        """
        Retrieves the spend private key used in this MoneroHD instance.

        :return: Spend private key used in this instance, or None if not set.
        :rtype: Optional[str]
        """

    def view_private_key(self) -> str:
        """
        Retrieves the view private key used in this MoneroHD instance.

        :return: View private key used in this instance.
        :rtype: str
        """

    def wif(self, *args, **kwargs) -> Optional[str]:
        """
        Converts the private key to a WIF (Wallet Import Format) string.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The WIF representation of the private key, or None if the private key is not set.
        :rtype: Optional[str]
        """

    def wif_type(self) -> str:
        """
        Retrieves the current WIF (Wallet Import Format) type used by the instance.

        :return: The current WIF type if a WIF is present, otherwise None.
        :rtype: Optional[str]
        """

    def chain_code(self) -> str:
        """
        Retrieves the chain code associated with the current instance.

        :return: The chain code as a string if available, otherwise None.
        :rtype: Optional[str]
        """

    def public_key(self, *args, **kwargs) -> str:
        """
        Retrieves the public key associated with the current instance.

        :param args: Additional positional arguments.
        :param kwargs: Additional keyword arguments.

        :return: The public key as a string based on the specified type.
        :rtype: str
        """

    def compressed(self) -> str:
        """
        Retrieves the compressed form of the public key associated with the current instance.

        :return: The compressed public key.
        :rtype: str
        """

    def uncompressed(self) -> str:
        """
        Retrieves the uncompressed form of the public key associated with the current instance.

        :return: The uncompressed public key.
        :rtype: str
        """

    def spend_public_key(self) -> str:
        """
        Retrieves the spend public key used in this MoneroHD instance.

        :return: Spend public key used in this instance.
        :rtype: str
        """

    def view_public_key(self) -> str:
        """
        Retrieves the view public key used in this MoneroHD instance.

        :return: View public key used in this instance.
        :rtype: str
        """

    def public_key_type(self) -> str:
        """
        Retrieves the type of public key associated with the current instance.

        :return: The type of public key.
        :rtype: str
        """

    def mode(self) -> str:
        """
        Get the mode of the ElectrumV2HD instance.

        :return: The mode of the instance.
        :rtype: str
        """

    def hash(self) -> str:
        """
        Retrieves the hash of the public key.

        :return: The hash of the public key.
        :rtype: str
        """

    def fingerprint(self) -> str:
        """
        Computes the fingerprint of the HD object by hashing the public key.

        :return: The fingerprint of the HD object.
        :rtype: str
        """

    def parent_fingerprint(self) -> str:
        """
        Retrieves the parent fingerprint of the HD object.

        :return: The parent fingerprint if available, otherwise None.
        :rtype: Optional[str]
        """

    def depth(self) -> int:
        """
        Retrieves the depth of the HD object in the hierarchical tree.

        :return: The depth of the object.
        :rtype: int
        """

    def path(self) -> str:
        """
        Retrieves the derivation path associated with the HD object.

        :return: The derivation path.
        :rtype: str
        """

    def path_key(self) -> str:
        """
        Retrieves the derivation path key associated with the HD object.

        :return: The derivation path.
        :rtype: str
        """

    def index(self) -> int:
        """
        Retrieves the index of the current BIP32HD object.

        :return: The index value.
        :rtype: int
        """

    def indexes(self) -> List[int]:
        """
        Retrieves the list of indexes from the derivation associated with this BIP32HD object.

        :return: The list of indexes.
        :rtype: List[int]
        """

    def strict(self) -> Optional[bool]:
        """
        Retrieves the strict mode flag associated with this BIP32HD object.

        :return: The strict mode flag.
        :rtype: Optional[bool]
        """

    def integrated_address(self, **kwargs) -> str:
        """
        Generates the integrated Monero address associated with the spend and view public keys.

        :param kwargs: Additional keyword arguments.

        :return: Integrated Monero address.
        :rtype: str
        """

    def primary_address(self, **kwargs) -> str:
        """
        Generates the primary Monero address associated with the spend and view public keys.

        :param kwargs: Additional keyword arguments.

        :return: Primary Monero address.
        :rtype: str
        """

    def sub_address(self, **kwargs) -> str:
        """
        Generates a sub-address associated with the given minor and major indexes or uses the current derivation indexes.

        :param kwargs: Additional keyword arguments.

        :return: Generated sub-address.
        :rtype: str
        """

    def address(self, **kwargs) -> str:
        """
        Generates an address based on the specified type and parameters.

        :param kwargs: Additional keyword arguments.

        :return: The generated address.
        :rtype: str
        """
