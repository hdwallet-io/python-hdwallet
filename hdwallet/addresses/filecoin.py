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
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Filecoin
from ..crypto import (
    blake2b_32, blake2b_160
)
from ..utils import (
    get_bytes, integer_to_bytes, bytes_to_string
)
from ..exceptions import AddressError
from .iaddress import IAddress


class FilecoinAddress(IAddress):

    alphabet: str = Filecoin.PARAMS.ALPHABET
    address_prefix: str = Filecoin.PARAMS.ADDRESS_PREFIX
    address_types: dict = {
        "secp256k1": Filecoin.PARAMS.ADDRESS_TYPES.SECP256K1,
        "bls": Filecoin.PARAMS.ADDRESS_TYPES.BLS
    }

    @staticmethod
    def name() -> str:
        """
        Returns the name of the blockchain.

        :return: The name of the blockchain.
        :rtype: str
        """

        return "Filecoin"

    @classmethod
    def compute_checksum(cls, public_key_hash: bytes, address_type: int) -> bytes:
        return blake2b_32(
            integer_to_bytes(address_type) + public_key_hash
        )

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes the given public key into a Filecoin address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments, including "address_type".
        :type kwargs: Any

        :return: The encoded Filecoin address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = blake2b_160(
            public_key.raw_uncompressed()
        )

        if not kwargs.get("address_type"):
            address_type: int = cls.address_types[Filecoin.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Filecoin.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Filecoin.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: int = cls.address_types[kwargs.get("address_type")]

        checksum: bytes = cls.compute_checksum(public_key_hash, address_type)
        base32_encode: str = encode_no_padding(
            (public_key_hash + checksum).hex(), cls.alphabet
        )
        return (
            cls.address_prefix + chr(address_type + ord("0")) + base32_encode
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes the given Filecoin address into its corresponding public key hash.

        :param address: The Filecoin address to be decoded.
        :type address: str
        :param kwargs: Additional keyword arguments, including "address_type".
        :type kwargs: Any

        :return: The decoded public key hash.
        :rtype: str
        """

        prefix_got: str = address[:len(cls.address_prefix)]
        if cls.address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {cls.address_prefix}, got: {prefix_got})")
        address_no_prefix: str = address[len(cls.address_prefix):]

        if not kwargs.get("address_type"):
            address_type: int = cls.address_types[Filecoin.PARAMS.DEFAULT_ADDRESS_TYPE]
        else:
            if kwargs.get("address_type") not in Filecoin.ADDRESS_TYPES.get_address_types():
                raise AddressError(
                    f"Invalid {cls.name()} address type",
                    expected=Filecoin.ADDRESS_TYPES.get_address_types(),
                    got=kwargs.get("address_type")
                )
            address_type: int = cls.address_types[kwargs.get("address_type")]

        address_type_got = ord(address_no_prefix[0]) - ord("0")
        if address_type != address_type_got:
            raise ValueError(f"Invalid address type (expected: {address_type}, got: {address_type_got})")

        address_decode: bytes = get_bytes(decode(address_no_prefix[1:], cls.alphabet))

        if len(address_decode) != 24:
            raise ValueError(f"Invalid length (expected: {24}, got: {len(address_decode)})")

        checksum: bytes = address_decode[-1 * 4:]
        public_key_hash: bytes = address_decode[:-1 * 4]

        checksum_got: bytes = cls.compute_checksum(public_key_hash, address_type)
        if checksum != checksum_got:
            raise ValueError(f"Invalid checksum (expected: {checksum.hex()}, got: {checksum_got.hex()})")

        return bytes_to_string(public_key_hash)
