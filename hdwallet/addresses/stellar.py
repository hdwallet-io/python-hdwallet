#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base32 import (
    encode_no_padding, decode
)
from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Stellar
from ..crypto import xmodem_crc
from ..utils import (
    get_bytes, bytes_reverse, integer_to_bytes, bytes_to_string
)
from ..exceptions import AddressError
from .iaddress import IAddress


class StellarAddress(IAddress):

    checksum_length: int = Stellar.PARAMS.CHECKSUM_LENGTH
    address_types: dict = {
        "private_key": Stellar.PARAMS.ADDRESS_TYPES.PRIVATE_KEY,
        "public_key": Stellar.PARAMS.ADDRESS_TYPES.PUBLIC_KEY
    }

    @staticmethod
    def name() -> str:
        """
        Return the name of the cryptocurrency, which is "Stellar".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Stellar"

    @staticmethod
    def compute_checksum(public_key: bytes) -> bytes:
        return bytes_reverse(xmodem_crc(public_key))

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a Stellar address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]

        :param kwargs: Additional keyword arguments.
            - address_type: Type of the Stellar address (optional).
        :type kwargs: Any

        :return: The encoded Stellar address.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: int = cls.address_types[Stellar.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Stellar.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Stellar.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: int = cls.address_types[kwargs.get("address_type")]

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        payload: bytes = integer_to_bytes(address_type) + public_key.raw_compressed()[1:]
        checksum: bytes = cls.compute_checksum(payload)

        return encode_no_padding((payload + checksum).hex())

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a Stellar address back into its public key representation.

        :param address: The Stellar address to decode.
        :type address: str

        :param kwargs: Additional keyword arguments.
            - address_type: Type of the Stellar address (optional).
        :type kwargs: Any

        :return: The decoded public key as a string.
        :rtype: str
        """

        if not kwargs.get("address_type"):
            address_type: int = cls.address_types[Stellar.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Stellar.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Stellar.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: int = cls.address_types[kwargs.get("address_type")]

        address_decode: bytes = get_bytes(decode(address))
        expected_length: int = (
            SLIP10Ed25519PublicKey.compressed_length() + cls.checksum_length
        )
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        checksum: bytes = address_decode[-1 * cls.checksum_length:]
        payload: bytes = address_decode[:-1 * cls.checksum_length]

        address_type_got: int = payload[0]
        if address_type != address_type_got:
            raise ValueError(f"Invalid address type (expected: {address_type}, got: {address_type_got})")

        checksum_got: bytes = cls.compute_checksum(payload)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {bytes_to_string(checksum)}, got: {bytes_to_string(checksum_got)})")

        public_key: bytes = payload[1:]
        if not SLIP10Ed25519PublicKey.is_valid_bytes(public_key):
            raise ValueError(f"Invalid {SLIP10Ed25519PublicKey.name()} public key {bytes_to_string(public_key)}")

        return bytes_to_string(public_key)
