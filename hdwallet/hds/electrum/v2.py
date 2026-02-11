#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Optional
)

from ...addresses import (
    P2PKHAddress, P2WPKHAddress
)
from ...seeds import ISeed
from ...eccs import SLIP10Secp256k1ECC
from ...derivations import CustomDerivation
from ...wif import private_key_to_wif
from ...derivations import (
    IDerivation, ElectrumDerivation
)
from ...cryptocurrencies import Bitcoin
from ...consts import (
    PUBLIC_KEY_TYPES, MODES, WIF_TYPES
)
from ...exceptions import (
    Error, DerivationError, AddressError
)
from ..bip32 import BIP32HD
from ..ihd import IHD


class ElectrumV2HD(IHD):

    _mode: str
    _wif_type: str
    _public_key_type: str
    _wif_prefix: Optional[int] = None
    _derivation: ElectrumDerivation

    def __init__(
        self, mode: str = MODES.STANDARD, public_key_type: str = PUBLIC_KEY_TYPES.UNCOMPRESSED, **kwargs
    ) -> None:
        """
        Initialize an instance of ElectrumV2HD.

        :param mode: The mode of operation (default is 'standard').
        :type mode: str

        :param public_key_type: The type of public key to use ('uncompressed' or 'compressed').
        :type public_key_type: str

        :param kwargs: Additional keyword arguments.
        """

        super(ElectrumV2HD, self).__init__(
            ecc=SLIP10Secp256k1ECC, **kwargs
        )

        if mode not in MODES.get_modes():
            raise Error(
                f"Invalid {self.name()} mode", expected=MODES.get_modes(), got=mode
            )
        self._mode = mode

        if public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            self._wif_type = WIF_TYPES.WIF
        elif public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            self._wif_type = WIF_TYPES.WIF_COMPRESSED
        else:
            raise Error(
                f"Invalid {self.name()} public key type", expected=PUBLIC_KEY_TYPES.get_types(), got=public_key_type
            )
        self._wif_prefix = kwargs.get("wif_prefix", Bitcoin.NETWORKS.MAINNET.WIF_PREFIX)
        self._public_key_type = public_key_type
        self._bip32_hd: BIP32HD = BIP32HD(
            ecc=Bitcoin.ECC, public_key_type=self._public_key_type
        )
        self._derivation = ElectrumDerivation(
            change=kwargs.get("change", 0),
            address=kwargs.get("address", 0)
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the v2 class.

        :return: The name of the v2 class.
        :rtype: str
        """

        return "Electrum-V2"

    def __update__(self) -> "ElectrumV2HD":
        """
        Update the instance using the current derivation.

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        self.from_derivation(derivation=self._derivation)
        return self

    def from_seed(self, seed: Union[bytes, str, ISeed], **kwargs) -> "ElectrumV2HD":
        """
        Initialize the instance from a seed.

        :param seed: The seed to derive keys from, can be bytes, str, or an ISeed object.
        :type seed: Union[bytes, str, ISeed]
        :param kwargs: Additional keyword arguments.

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        self._bip32_hd.from_seed(seed=seed)
        self.__update__()
        return self

    def from_derivation(self, derivation: IDerivation) -> "ElectrumV2HD":
        """
        Initialize the instance from a derivation.

        :param derivation: The derivation instance to set.
        :type derivation: IDerivation

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        if not isinstance(derivation, ElectrumDerivation):
            raise DerivationError(
                f"Invalid {self.name()} derivation instance", expected=ElectrumDerivation.name(), got=derivation.name()
            )

        self._derivation = derivation
        self.drive(
            change_index=self._derivation.change(),
            address_index=self._derivation.address(),
        )
        return self

    def update_derivation(self, derivation: IDerivation) -> "ElectrumV2HD":
        """
        Update the derivation instance of the ElectrumV2HD object.

        :param derivation: The new derivation instance to update.
        :type derivation: IDerivation

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        return self.from_derivation(derivation=derivation)

    def clean_derivation(self) -> "ElectrumV2HD":
        """
        Clean up the derivation instance of the ElectrumV2HD object and update the instance.

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        self._derivation.clean()
        self.__update__()
        return self

    def drive(self, change_index: int, address_index: int) -> "ElectrumV2HD":
        """
        Drive the derivation of keys based on the change index and address index.

        :param change_index: The change index.
        :type change_index: int
        :param address_index: The address index.
        :type address_index: int

        :return: Updated instance of ElectrumV2HD.
        :rtype: ElectrumV2HD
        """

        custom_derivation: CustomDerivation = CustomDerivation()
        if self._mode == MODES.SEGWIT:
            custom_derivation.from_index(index=0, hardened=True)
        custom_derivation.from_index(index=change_index)  # Change index
        custom_derivation.from_index(index=address_index)  # Address index
        self._bip32_hd.update_derivation(derivation=custom_derivation)
        return self

    def mode(self) -> str:
        """
        Get the mode of the ElectrumV2HD instance.

        :return: The mode of the instance.
        :rtype: str
        """

        return self._mode

    def seed(self) -> str:
        """
        Get the seed used in the BIP32HD instance.

        :return: The seed used.
        :rtype: str
        """
        return self._bip32_hd.seed()

    def master_private_key(self) -> Optional[str]:
        """
        Get the master private key of the BIP32HD instance.

        :return: The master private key as a string, or None if not available.
        :rtype: Optional[str]
        """

        return self._bip32_hd.root_private_key()

    def master_wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Get the master WIF (Wallet Import Format) for the specified WIF type.

        :param wif_type: The type of WIF format to use. Defaults to None (uses self._wif_type).
        :type wif_type: Optional[str]

        :return: The master WIF for the specified type, or None if the master private key is not available.
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
        )

    def master_public_key(self, public_key_type: Optional[str] = None) -> str:
        """
        Get the master public key in the specified public key type.

        :param public_key_type: The type of public key format to return. Defaults to None (uses self._public_key_type).
        :type public_key_type: Optional[str]

        :return: The master public key in the specified format.
        :rtype: str
        """

        _public_key_type: str = (
            public_key_type if public_key_type in PUBLIC_KEY_TYPES.get_types() else self._public_key_type
        )
        return self._bip32_hd.root_public_key(
            public_key_type=_public_key_type
        )

    def private_key(self) -> Optional[str]:
        """
        Get the current private key associated with this instance.

        :return: The current private key as a string if available, otherwise None.
        :rtype: Optional[str]
        """
        return self._bip32_hd.private_key()

    def wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Get the Wallet Import Format (WIF) representation of the current private key.

        :param wif_type: Optional. The type of WIF format to use. Defaults to the instance's configured WIF type.
        :type wif_type: Optional[str]

        :return: The WIF representation of the current private key if available, otherwise None.
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
            private_key=self.private_key(), wif_type=_wif_type, wif_prefix=self._wif_prefix
        )

    def wif_type(self) -> str:
        """
        Get the current type of Wallet Import Format (WIF) used by this instance.

        :return: The current WIF type.
        :rtype: str
        """
        return self._wif_type

    def public_key(self, public_key_type: Optional[str] = None) -> str:
        """
        Get the public key associated with this instance, optionally specifying the public key type.

        :param public_key_type: Optional parameter to specify the type of public key format.
                                If not provided, defaults to the current instance's public key type.
        :type public_key_type: Optional[str]

        :return: The public key in the specified format.
        :rtype: str
        """
        _public_key_type: str = (
            public_key_type if public_key_type in PUBLIC_KEY_TYPES.get_types() else self._public_key_type
        )
        return self._bip32_hd.public_key(
            public_key_type=_public_key_type
        )

    def public_key_type(self) -> str:
        """
        Get the current public key type used by this instance.

        :return: The current public key type.
        :rtype: str
        """

        return self._public_key_type

    def uncompressed(self) -> str:
        """
        Get the uncompressed representation of the master public key.

        :return: Uncompressed master public key.
        :rtype: str
        """

        return self._bip32_hd.uncompressed()

    def compressed(self) -> str:
        """
        Get the compressed representation of the master public key.

        :return: Compressed master public key.
        :rtype: str
        """

        return self._bip32_hd.compressed()

    def address(
        self,
        public_key_address_prefix: int = Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX,
        hrp: str = Bitcoin.NETWORKS.MAINNET.HRP,
        witness_version: str = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH,
    ) -> str:
        """
        Get the address based on the current mode.

        :param public_key_address_prefix: Public key address prefix for P2PKH addresses default: mainnet.
        :type public_key_address_prefix: int
        :param hrp: Human-readable part for SegWit addresses default: mainnet.
        :type hrp: str
        :param witness_version: Witness version for SegWit addresses default: P2WPKH.
        :type witness_version: str

        :return: Generated address based on the current mode.
        :rtype: str
        """

        if self._mode == MODES.STANDARD:
            return P2PKHAddress.encode(
                public_key=self.public_key(),
                public_key_address_prefix=public_key_address_prefix,
                public_key_type=self._public_key_type
            )
        elif self._mode == MODES.SEGWIT:
            return P2WPKHAddress.encode(
                public_key=self.public_key(),
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        raise AddressError(
            f"Invalid {self.name()} mode", expected=MODES.get_modes(), got=self._mode
        )
