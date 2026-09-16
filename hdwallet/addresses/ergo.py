#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import (
    ensure_string, encode, decode
)
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Ergo
from ..crypto import blake2b_256
from ..utils import (
    integer_to_bytes, bytes_to_string
)
from ..exceptions import (
    AddressError, NetworkError
)
from .iaddress import IAddress


class ErgoAddress(IAddress):

    checksum_length: int = Ergo.PARAMS.CHECKSUM_LENGTH
    address_types: dict = {
        "p2pkh": Ergo.PARAMS.ADDRESS_TYPES.P2PKH,
        "p2sh": Ergo.PARAMS.ADDRESS_TYPES.P2SH
    }
    network_types: dict = {
        "mainnet": Ergo.NETWORKS.MAINNET.TYPE,
        "testnet": Ergo.NETWORKS.TESTNET.TYPE
    }

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Ergo"

    @classmethod
    def compute_checksum(cls, public_key: bytes) -> bytes:
        return blake2b_256(public_key)[:cls.checksum_length]

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into an Ergo address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments, including "address_type" and "network_type".
        :type kwargs: Any

        :return: The encoded Ergo address.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: str = cls.address_types[Ergo.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Ergo.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Ergo.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: str = cls.address_types[kwargs.get("address_type")]

        if not kwargs.get("network_type"):
            raise NetworkError(f"{cls.name()} network type is required")
        elif kwargs.get("network_type") not in Ergo.NETWORKS.get_networks():
            raise NetworkError(
                f"Invalid {cls.name()} network type",
                expected=Ergo.NETWORKS.get_networks(),
                got=kwargs.get("network_type")
            )
        network_type = cls.network_types[kwargs.get("network_type")]

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        prefix: bytes = integer_to_bytes(address_type + network_type)
        address_payload: bytes = prefix + public_key.raw_compressed()
        checksum: bytes = cls.compute_checksum(address_payload)

        return ensure_string(encode(
            address_payload + checksum
        ))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Ergo address into its corresponding public key.

        :param address: The Ergo address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments, including "address_type" and "network_type".
        :type kwargs: Any

        :return: The decoded public key.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: str = cls.address_types[Ergo.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Ergo.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Ergo.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: str = cls.address_types[kwargs.get("address_type")]

        if not kwargs.get("network_type"):
            raise NetworkError(f"{cls.name()} network type is required")
        elif kwargs.get("network_type") not in Ergo.NETWORKS.get_networks():
            raise NetworkError(
                f"Invalid {cls.name()} network type",
                expected=Ergo.NETWORKS.get_networks(),
                got=kwargs.get("network_type")
            )
        network_type = cls.network_types[kwargs.get("network_type")]

        prefix: bytes = integer_to_bytes(address_type + network_type)
        address_decode: bytes = decode(address)

        expected_length: int = SLIP10Secp256k1PublicKey.compressed_length() + cls.checksum_length + 1
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        checksum: bytes = address_decode[-1 * cls.checksum_length:]
        address_with_prefix: bytes = address_decode[:-1 * cls.checksum_length]

        checksum_got: bytes = cls.compute_checksum(address_with_prefix)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {checksum.hex()}, got: {checksum_got.hex()})")

        prefix_got: bytes = address_with_prefix[:len(prefix)]
        if prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {prefix}, got: {prefix_got})")
        public_key: bytes = address_with_prefix[len(prefix):]

        if not SLIP10Secp256k1PublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Secp256k1PublicKey.name()} public key {public_key.hex()}")

        return bytes_to_string(public_key)
