#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union, Tuple, Type
)

from ..libs.ed25519 import scalar_reduce, int_decode
from ..eccs import (
    SLIP10Ed25519MoneroECC, IPoint, IPublicKey, IPrivateKey, SLIP10Ed25519MoneroPublicKey, SLIP10Ed25519MoneroPrivateKey
)
from ..seeds import ISeed
from ..crypto import kekkak256
from ..cryptocurrencies.icryptocurrency import INetwork
from ..cryptocurrencies import Monero
from ..derivations import (
    IDerivation, MoneroDerivation
)
from ..exceptions import (
    NetworkError, DerivationError, AddressError, PrivateKeyError, PublicKeyError, SeedError
)
from ..utils import (
    get_bytes, bytes_to_string, integer_to_bytes, bytes_to_integer
)
from ..addresses import MoneroAddress
from .ihd import IHD


class MoneroHD(IHD):

    _network: INetwork
    _seed: Optional[bytes] = None
    _private_key: Optional[bytes] = None

    _spend_private_key: Optional[IPrivateKey]
    _view_private_key: Union[IPrivateKey]
    _spend_public_key: Union[IPublicKey]
    _view_public_key: Union[IPublicKey]

    _derivation: MoneroDerivation

    def __init__(self, network: Union[str, Type[INetwork]] = "mainnet", **kwargs) -> None:
        """
        Initializes a new instance of the Monero class.


        :param network: Network identifier or type implementing the INetwork interface. Default is "mainnet".
        :type network: Union[str, Type[INetwork]]
        :param kwargs: Additional optional parameters:
        """

        super(MoneroHD, self).__init__(
            ecc=SLIP10Ed25519MoneroECC, **kwargs
        )

        try:
            if not isinstance(network, str) and issubclass(network, INetwork):
                network = network.NAME
            if not Monero.NETWORKS.is_network(network=network):
                raise NetworkError(
                    f"Wrong {Monero.NAME} network",
                    expected=Monero.NETWORKS.get_networks(),
                    got=network
                )
            self._network = Monero.NETWORKS.get_network(network=network)
        except TypeError:
            raise NetworkError(
                "Invalid network type", expected=[str, INetwork], got=type(network)
            )

        self._derivation = MoneroDerivation(
            minor=kwargs.get("minor", 1), major=kwargs.get("major", 0)
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the monero class.

        :return: The name of the monero class.
        :rtype: str
        """
        return "Monero"

    def __update__(self) -> "MoneroHD":
        """
        Update the MoneroHD instance using the current derivation parameters.

        :return: Updated MoneroHD instance.
        :rtype: MoneroHD
        """

        self.from_derivation(derivation=self._derivation)
        return self

    def from_seed(self, seed: Union[bytes, str, ISeed], **kwargs) -> "MoneroHD":
        """
        Initialize the MoneroHD instance from a seed value.

        :param seed: Seed value to initialize the HD wallet.
        :type seed: Union[bytes, str, ISeed]
        :param kwargs: Additional keyword arguments for customization.

        :return: Initialized MoneroHD instance.
        :rtype: MoneroHD
        """

        try:
            self._seed = get_bytes(
                seed.seed() if isinstance(seed, ISeed) else seed
            )
            spend_private_key: bytes = (
                self._seed if len(self._seed) == SLIP10Ed25519MoneroPrivateKey.length() else kekkak256(self._seed)
            )
            return self.from_spend_private_key(
                spend_private_key=scalar_reduce(spend_private_key)
            )
        except ValueError as error:
            raise SeedError("Invalid seed data") from error

    def from_private_key(self, private_key: Union[bytes, str, IPrivateKey]) -> "MoneroHD":
        """
        Initialize the MoneroHD instance from a private key.

        :param private_key: Private key value to initialize the HD wallet.
        :type private_key: Union[bytes, str, IPrivateKey]

        :return: Initialized MoneroHD instance.
        :rtype: MoneroHD
        """

        try:
            self._private_key = (
                private_key.raw() if isinstance(private_key, SLIP10Ed25519MoneroPrivateKey) else get_bytes(private_key)
            )
            return self.from_spend_private_key(
                spend_private_key=scalar_reduce(kekkak256(self._private_key))
            )
        except ValueError as error:
            raise PrivateKeyError("Invalid private key data") from error

    def from_derivation(self, derivation: IDerivation) -> "MoneroHD":
        """
        Initialize the MoneroHD instance from a derivation object.

        :param derivation: Derivation object to initialize the HD wallet.
        :type derivation: IDerivation

        :return: Initialized MoneroHD instance.
        :rtype: MoneroHD
        """

        if not isinstance(derivation, MoneroDerivation):
            raise DerivationError(
                f"Invalid {self.name()} derivation instance", expected=MoneroDerivation, got=type(derivation)
            )

        self._derivation = derivation
        return self

    def update_derivation(self, derivation: IDerivation) -> "MoneroHD":
        """
        Update the current derivation of the MoneroHD instance.

        :param derivation: New derivation object to update the HD wallet's derivation.
        :type derivation: IDerivation

        :return: Updated MoneroHD instance with the new derivation.
        :rtype: MoneroHD
        """
        return self.from_derivation(derivation=derivation)

    def clean_derivation(self) -> "MoneroHD":
        """
        Clean up the current derivation state of the MoneroHD instance.

        :return: Updated MoneroHD instance with cleaned derivation.
        :rtype: MoneroHD
        """
        self._derivation.clean()
        self.__update__()
        return self

    def from_spend_private_key(self, spend_private_key: Union[bytes, str, IPrivateKey]) -> "MoneroHD":
        """
        Initialize the MoneroHD instance from a spend private key.

        :param spend_private_key: Spend private key to initialize from.
        :type spend_private_key: Union[bytes, str, IPrivateKey]

        :return: Updated MoneroHD instance initialized from the spend private key.
        :rtype: MoneroHD
        """

        if isinstance(spend_private_key, (bytes, str)):
            spend_private_key: IPrivateKey = SLIP10Ed25519MoneroPrivateKey.from_bytes(get_bytes(spend_private_key))

        self._spend_private_key = spend_private_key
        self._view_private_key = SLIP10Ed25519MoneroPrivateKey.from_bytes(
            scalar_reduce(kekkak256(spend_private_key.raw()))
        )
        self._spend_public_key = self._spend_private_key.public_key()
        self._view_public_key = self._view_private_key.public_key()
        return self

    def from_watch_only(
        self, view_private_key: Union[bytes, str, IPrivateKey], spend_public_key: Union[bytes, str, IPublicKey]
    ) -> "MoneroHD":
        """
        Initialize the MoneroHD instance from watch-only keys.

        :param view_private_key: View private key or seed to initialize from.
        :type view_private_key: Union[bytes, str, IPrivateKey]
        :param spend_public_key: Spend public key to initialize from.
        :type spend_public_key: Union[bytes, str, IPublicKey]

        :return: Updated MoneroHD instance initialized from the watch-only keys.
        :rtype: MoneroHD
        """

        try:
            if isinstance(view_private_key, (bytes, str)):
                view_private_key: IPrivateKey = SLIP10Ed25519MoneroPrivateKey.from_bytes(get_bytes(view_private_key))
        except ValueError as error:
            raise PrivateKeyError("Invalid view private key data") from error

        try:
            if isinstance(spend_public_key, (bytes, str)):
                spend_public_key: IPublicKey = SLIP10Ed25519MoneroPublicKey.from_bytes(get_bytes(spend_public_key))
        except ValueError as error:
            raise PublicKeyError("Invalid spend public key data") from error

        self._spend_private_key = None
        self._view_private_key = view_private_key
        self._spend_public_key = spend_public_key
        self._view_public_key = self._view_private_key.public_key()
        return self

    def drive(self, minor_index: int, major_index: int) -> Tuple[IPublicKey, IPublicKey]:
        """
        Derives sub-address public keys based on given minor and major indices.

        :param minor_index: Minor index for sub-address derivation.
        :type minor_index: int
        :param major_index: Major index for sub-address derivation.
        :type major_index: int

        :return: Tuple containing the derived sub-address spend and view public keys.
        :rtype: Tuple[IPublicKey, IPublicKey]
        """

        maximum_index: int = 2 ** 32 - 1
        if minor_index < 0 or minor_index > maximum_index:
            raise DerivationError(
                "Invalid minor index range", expected=f"0-{maximum_index}", got=minor_index
            )
        if major_index < 0 or major_index > maximum_index:
            raise DerivationError(
                "Invalid major index range", expected=f"0-{maximum_index}", got=major_index
            )

        if minor_index == 0 and major_index == 0:
            return self._spend_public_key, self._view_public_key

        m: int = int_decode(scalar_reduce(
            kekkak256(
                b"SubAddr\x00" +
                self._view_private_key.raw() +
                integer_to_bytes(
                    major_index, bytes_num=4, endianness="little"
                ) + integer_to_bytes(
                    minor_index, bytes_num=4, endianness="little"
                )
            )
        ))

        sub_address_spend_public_key: IPoint = (
            self._spend_public_key.point() + (SLIP10Ed25519MoneroECC.GENERATOR * m)
        )
        sub_address_view_public_key: IPoint = (
            sub_address_spend_public_key * bytes_to_integer(
                self._view_private_key.raw(), endianness="little"
            )
        )

        return (
            SLIP10Ed25519MoneroPublicKey.from_point(sub_address_spend_public_key),
            SLIP10Ed25519MoneroPublicKey.from_point(sub_address_view_public_key)
        )

    def seed(self) -> Optional[str]:
        """
        Retrieves the seed used in this MoneroHD instance.

        :return: Seed used in this instance, or None if not set.
        :rtype: Optional[str]
        """
        return bytes_to_string(self._seed) if self._seed else None

    def private_key(self) -> Optional[str]:
        """
        Retrieves the private key used in this MoneroHD instance.

        :return: Private key used in this instance, or None if not set.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._private_key) if self._private_key else None

    def spend_private_key(self) -> Optional[str]:
        """
        Retrieves the spend private key used in this MoneroHD instance.

        :return: Spend private key used in this instance, or None if not set.
        :rtype: Optional[str]
        """
        return bytes_to_string(self._spend_private_key.raw()) if self._spend_private_key else None

    def view_private_key(self) -> str:
        """
        Retrieves the view private key used in this MoneroHD instance.

        :return: View private key used in this instance.
        :rtype: str
        """

        return bytes_to_string(
            self._view_private_key.raw()
        )

    def spend_public_key(self) -> str:
        """
        Retrieves the spend public key used in this MoneroHD instance.

        :return: Spend public key used in this instance.
        :rtype: str
        """

        return bytes_to_string(self._spend_public_key.raw_compressed())

    def view_public_key(self) -> str:
        """
        Retrieves the view public key used in this MoneroHD instance.

        :return: View public key used in this instance.
        :rtype: str
        """

        return bytes_to_string(self._view_public_key.raw_compressed())

    def primary_address(self) -> str:
        return MoneroAddress.encode(
            spend_public_key=self._spend_public_key,
            view_public_key=self._view_public_key,
            network=self._network.NAME,
            address_type=Monero.ADDRESS_TYPES.STANDARD,
            payment_id=None
        )

    def integrated_address(self, payment_id: Union[bytes, str]) -> str:
        """
        Generates the primary Monero address associated with the spend and view public keys.

        :return: Primary Monero address.
        :rtype: str
        """

        return MoneroAddress.encode(
            spend_public_key=self._spend_public_key,
            view_public_key=self._view_public_key,
            network=self._network.NAME,
            address_type=Monero.ADDRESS_TYPES.INTEGRATED,
            payment_id=get_bytes(payment_id)
        )

    def sub_address(self, minor: Optional[int] = None, major: Optional[int] = None) -> str:
        """
        Generates a sub-address associated with the given minor and major indexes or uses the current derivation indexes.

        :param minor: Minor index for sub-address derivation.
        :type minor: Optional[int]

        :param major: Major index for sub-address derivation.
        :type major: Optional[int]

        :return: Generated sub-address.
        :rtype: str
        """

        if minor is None and major is None:
            minor, major = self._derivation.minor(), self._derivation.major()
        elif (minor and major is None) or (minor is None and major):
            raise DerivationError("Both minor and major indexes are required")

        if minor == 0 and major == 0:
            return self.primary_address()

        spend_public_key, view_public_key = self.drive(
            minor_index=minor, major_index=major
        )

        return MoneroAddress.encode(
            spend_public_key=spend_public_key,
            view_public_key=view_public_key,
            network=self._network.NAME,
            address_type="sub-address",
            payment_id=None
        )

    def address(self, address_type: str, **kwargs) -> str:
        """
        Generates a Monero address of the specified type.

        :param address_type: str - Type of Monero address to generate.
        :type address_type: str

        :param kwargs: Additional keyword arguments depending on the address type:

        :return: str - Generated Monero address.
        """

        if address_type == Monero.ADDRESS_TYPES.STANDARD:
            return self.primary_address()
        elif address_type == Monero.ADDRESS_TYPES.INTEGRATED:
            return self.integrated_address(
                payment_id=kwargs.get("payment_id")
            )
        elif address_type == Monero.ADDRESS_TYPES.SUB_ADDRESS:
            return self.sub_address(
                minor=kwargs.get("minor", self._derivation.minor()),
                major=kwargs.get("major", self._derivation.major())
            )
        raise AddressError(
            f"Invalid {self.name()} address type",
            expected=Monero.ADDRESS_TYPES.get_address_types(),
            got=address_type
        )
