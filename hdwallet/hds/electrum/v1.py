#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Optional
)

from ...eccs import (
    IPublicKey, IPrivateKey, SLIP10Secp256k1ECC, SLIP10Secp256k1PrivateKey, SLIP10Secp256k1PublicKey
)
from ...seeds import ISeed
from ...addresses import P2PKHAddress
from ...wif import (
    private_key_to_wif, wif_to_private_key
)
from ...consts import PUBLIC_KEY_TYPES
from ...derivations import (
    IDerivation, ElectrumDerivation
)
from ...crypto import double_sha256
from ...cryptocurrencies import Bitcoin
from ...exceptions import (
    Error, DerivationError, PublicKeyError, PrivateKeyError, SeedError, WIFError
)
from ...utils import (
    get_bytes, encode, bytes_to_string, bytes_to_integer, integer_to_bytes
)
from ...wif import WIF_TYPES
from ..ihd import IHD


class ElectrumV1HD(IHD):

    _seed: Optional[bytes] = None
    _master_private_key: Optional[IPrivateKey]
    _master_public_key: IPublicKey
    _private_key: Optional[IPrivateKey]
    _public_key: IPublicKey
    _public_key_type: str
    _wif_type: str
    _wif_prefix: Optional[int] = None
    _derivation: ElectrumDerivation

    def __init__(self, public_key_type: str = PUBLIC_KEY_TYPES.UNCOMPRESSED, **kwargs) -> None:
        """
        Initializes an instance of ElectrumV1HD.

        :param public_key_type: str - Type of public key to use (UNCOMPRESSED or COMPRESSED).
        :type public_key_type: str

        :param kwargs: Additional keyword arguments:
        """
        super(ElectrumV1HD, self).__init__(
            ecc=SLIP10Secp256k1ECC, public_key_type=public_key_type, **kwargs
        )

        if public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            self._wif_type = WIF_TYPES.WIF
        elif public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            self._wif_type = WIF_TYPES.WIF_COMPRESSED
        else:
            raise Error(
                "Invalid public key type", expected=PUBLIC_KEY_TYPES.get_types(), got=public_key_type
            )
        self._wif_prefix = kwargs.get("wif_prefix", Bitcoin.NETWORKS.MAINNET.WIF_PREFIX)
        self._public_key_type = public_key_type
        self._master_private_key = None
        self._private_key = None
        self._derivation = ElectrumDerivation(
            change=kwargs.get("change", 0),
            address=kwargs.get("address", 0)
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the v1 class.

        :return: The name of the v1 class.
        :rtype: str
        """
        return "Electrum-V1"

    def __update__(self) -> "ElectrumV1HD":
        """
        Updates the instance using current derivation parameters.

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        self.from_derivation(derivation=self._derivation)
        return self

    def from_seed(self, seed: Union[bytes, str, ISeed], **kwargs) -> "ElectrumV1HD":
        """
        Initializes the instance from a seed.

        :param seed: The seed to initialize from.
        :type seed: Union[bytes, str, ISeed]
        :param kwargs: Additional keyword arguments.

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        try:
            self._seed = get_bytes(
                seed.seed() if isinstance(seed, ISeed) else seed
            )
            self.from_private_key(private_key=self._seed)
            return self
        except ValueError as error:
            raise SeedError("Invalid seed data") from error

    def from_private_key(self, private_key: Union[bytes, str, IPrivateKey]) -> "ElectrumV1HD":
        """
        Initializes the instance from a private key.

        :param private_key: The private key to initialize from.
        :type private_key: Union[bytes, str, IPrivateKey]

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        try:
            if not isinstance(private_key, SLIP10Secp256k1PrivateKey):
                private_key: IPrivateKey = SLIP10Secp256k1PrivateKey.from_bytes(
                    get_bytes(private_key)
                )

            self._master_private_key, self._master_public_key = (
                private_key, private_key.public_key()
            )
            self.__update__()
            return self
        except ValueError as error:
            raise PrivateKeyError("Invalid private key data") from error

    def from_wif(self, wif: str) -> "ElectrumV1HD":
        """
        Initializes the instance from a WIF (Wallet Import Format) string.

        :param wif: The WIF string to initialize from.
        :type wif: str

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        if self._wif_prefix is None:
            raise WIFError("WIF prefix is required")

        return self.from_private_key(
            private_key=wif_to_private_key(wif=wif, wif_prefix=self._wif_prefix)
        )

    def from_public_key(self, public_key: Union[bytes, str, IPublicKey]) -> "ElectrumV1HD":
        """
        Initializes the instance from a public key.

        :param public_key: The public key to initialize from.
        :type public_key: Union[bytes, str, IPublicKey]

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        try:
            if not isinstance(public_key, SLIP10Secp256k1PublicKey):
                public_key: IPublicKey = SLIP10Secp256k1PublicKey.from_bytes(
                    get_bytes(public_key)
                )

            self._master_public_key = public_key
            self.__update__()
            return self
        except ValueError as error:
            raise PublicKeyError("Invalid public key error") from error

    def from_derivation(self, derivation: IDerivation) -> "ElectrumV1HD":
        """
        Initializes the instance from a derivation object.

        :param derivation: The derivation object to initialize from.
        :type derivation: IDerivation

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        if not isinstance(derivation, ElectrumDerivation):
            raise DerivationError(
                f"Invalid {self.name()} derivation instance", expected=ElectrumDerivation, got=type(derivation)
            )

        self._derivation = derivation
        self.drive(
            change_index=self._derivation.change(),
            address_index=self._derivation.address(),
        )
        return self

    def update_derivation(self, derivation: IDerivation) -> "ElectrumV1HD":
        """
        Updates the instance with a new derivation object.

        :param derivation: The new derivation object to update with.
        :type derivation: IDerivation

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        return self.from_derivation(derivation=derivation)

    def clean_derivation(self) -> "ElectrumV1HD":
        """
        Cleans up the derivation path and updates the instance.

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        self._derivation.clean()
        self.__update__()
        return self

    def drive(self, change_index: int, address_index: int) -> "ElectrumV1HD":
        """
        Drives the HD wallet by calculating keys based on the given change and address indexes.

        :param change_index: Index for change (0 or 1).
        :type change_index: int
        :param address_index: Index for address derivation.
        :type address_index: int

        :return: Updated instance of ElectrumV1HD.
        :rtype: ElectrumV1HD
        """

        sequence: bytes = double_sha256(
            encode(f"{address_index}:{change_index}:") + self._master_public_key.raw_uncompressed()[1:]
        )

        if self._master_private_key:
            private_key: int = (
                bytes_to_integer(self._master_private_key.raw()) + bytes_to_integer(sequence)
            ) % SLIP10Secp256k1ECC.ORDER
            self._private_key = SLIP10Secp256k1PrivateKey.from_bytes(
                integer_to_bytes(private_key, bytes_num=SLIP10Secp256k1PrivateKey.length())
            )
            self._public_key = self._private_key.public_key()
        else:
            self._public_key = SLIP10Secp256k1PublicKey.from_point(
                self._master_public_key.point() + bytes_to_integer(sequence) * SLIP10Secp256k1ECC.GENERATOR
            )
        return self

    def seed(self) -> Optional[str]:
        """
        Retrieves the seed used for key derivation.

        :return: Seed as a string if available, otherwise None.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._seed) if self._seed else None

    def master_private_key(self) -> Optional[str]:
        """
        Retrieves the master private key.

        :return: Master private key as a string if available, otherwise None.
        :rtype: Optional[str]
        """
        return bytes_to_string(self._master_private_key.raw()) if self._master_private_key else None

    def master_wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Retrieves the master private key in Wallet Import Format (WIF).

        :param wif_type: Optional parameter to specify the WIF type ('WIF' or 'WIF_COMPRESSED'). If not provided,
                        defaults to the type determined during initialization.
        :type wif_type: Optional[str]

        :return: Master private key in WIF format as a string if available, otherwise None.
        :rtype: Optional[str]
        """

        if self._wif_prefix is None:
            return None

        if wif_type:
            if wif_type not in WIF_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} WIF type", expected=WIF_TYPES.get_types(), got=wif_type
                )
            _wif_type: str = wif_type
        else:
            _wif_type: str = self._wif_type

        return private_key_to_wif(
            private_key=self.master_private_key(), wif_type=_wif_type, wif_prefix=self._wif_prefix
        ) if self.master_private_key() else None

    def master_public_key(self, public_key_type: Optional[str] = None) -> str:
        """
        Retrieves the master public key in the specified or default public key type.

        :param public_key_type: Optional parameter to specify the public key type ('uncompressed' or 'compressed').
                                If not provided, defaults to the type determined during initialization.
        :type public_key_type: Optional[str]

        :return: Master public key as a string.
        :rtype: str
        """
        _public_key_type: str = (
            public_key_type if public_key_type in PUBLIC_KEY_TYPES.get_types() else self._public_key_type
        )
        if _public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            return bytes_to_string(self._master_public_key.raw_uncompressed())
        elif _public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            return bytes_to_string(self._master_public_key.raw_compressed())
        raise Error(
            f"Invalid {self.name()} public key type", expected=PUBLIC_KEY_TYPES.get_types(), got=public_key_type
        )

    def private_key(self) -> Optional[str]:
        """
        Retrieves the private key as a string, if available.

        :return: Private key as a string if available, otherwise None.
        :rtype: Optional[str]
        """

        if not self._private_key:
            return None
        return bytes_to_string(self._private_key.raw())

    def wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Retrieves the Wallet Import Format (WIF) representation of the private key, if available.

        :param wif_type: Optional. The type of WIF format to use. If not specified, defaults to the instance's WIF type.
        :type wif_type: Optional[str]

        :return: WIF representation of the private key if available, otherwise None.
        :rtype: Optional[str]
        """

        if not self._private_key:
            return None

        if self._wif_prefix is None:
            return None

        if wif_type:
            if wif_type not in WIF_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} WIF type", expected=WIF_TYPES.get_types(), got=wif_type
                )
            _wif_type: str = wif_type
        else:
            _wif_type: str = self._wif_type

        return private_key_to_wif(
            private_key=self.private_key(), wif_type=_wif_type, wif_prefix=self._wif_prefix
        )

    def wif_type(self) -> str:
        """
        Retrieves the current type of Wallet Import Format (WIF) used by the instance.

        :return: The current WIF type.
        :rtype: str
        """

        return self._wif_type

    def public_key(self, public_key_type: Optional[str] = None) -> str:
        """
        Retrieves the public key of the specified type.

        :param public_key_type: Optional. The type of public key to retrieve ('uncompressed' or 'compressed').
                                Defaults to the type set in the instance.
        :type public_key_type: str

        :return: The public key string.
        :rtype: str
        """

        if public_key_type:
            if public_key_type not in PUBLIC_KEY_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} public key type", expected=PUBLIC_KEY_TYPES.get_types(), got=public_key_type
                )
            _public_key_type: str = public_key_type
        else:
            _public_key_type: str = self._public_key_type

        if _public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            return self.uncompressed()
        elif _public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            return self.compressed()

    def public_key_type(self) -> str:
        """
        Retrieves the current type of public key stored in the instance.

        :return: The current public key type.
        :rtype: str
        """

        return self._public_key_type

    def uncompressed(self) -> str:
        """
        Retrieves the uncompressed form of the stored public key.

        :return: The uncompressed public key as a string.
        :rtype: str
        """

        return bytes_to_string(self._public_key.raw_uncompressed())

    def compressed(self) -> str:
        """
        Retrieves the compressed form of the stored public key.

        :return: The compressed public key as a string.
        :rtype: str
        """

        return bytes_to_string(self._public_key.raw_compressed())

    def address(
        self, public_key_address_prefix: int = Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
    ) -> str:
        """
        Generates a Bitcoin address (P2PKH) from the stored public key.

        :param public_key_address_prefix: The prefix for the Bitcoin address default is mainnet.
        :type public_key_address_prefix: int

        :return: The generated Bitcoin address.
        :rtype: str
        """

        return P2PKHAddress.encode(
            public_key=self._public_key,
            public_key_address_prefix=public_key_address_prefix,
            public_key_type=self._public_key_type
        )
