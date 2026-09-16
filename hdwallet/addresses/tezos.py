#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import (
    check_encode, check_decode, ensure_string
)
from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Tezos
from ..crypto import blake2b_160
from ..utils import bytes_to_string
from ..exceptions import AddressError
from .iaddress import IAddress


class TezosAddress(IAddress):

    address_prefixes: dict = {
        "tz1": Tezos.PARAMS.ADDRESS_PREFIXES.TZ1,
        "tz2": Tezos.PARAMS.ADDRESS_PREFIXES.TZ2,
        "tz3": Tezos.PARAMS.ADDRESS_PREFIXES.TZ3
    }

    @staticmethod
    def name() -> str:
        """
        Get the name of the blockchain protocol.

        :return: The name of the blockchain protocol.
        :rtype: str
        """

        return "Tezos"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a Tezos address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - address_prefix: Address prefix (optional).
        :type kwargs: Any

        :return: The encoded Tezos address.
        :rtype: str
        """

        if not kwargs.get("address_prefix"):
            address_prefix: bytes = cls.address_prefixes[Tezos.DEFAULT_ADDRESS_PREFIX]
        else:
            if kwargs.get("address_prefix") not in Tezos.ADDRESS_PREFIXES.get_address_prefixes():
                raise AddressError(
                    f"Invalid {cls.name()} address prefix",
                    expected=Tezos.ADDRESS_PREFIXES.get_address_prefixes(),
                    got=kwargs.get("address_prefix")
                )
            address_prefix: bytes = cls.address_prefixes[kwargs.get("address_prefix")]

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        payload: bytes = blake2b_160(
            public_key.raw_compressed()[1:]
        )

        return ensure_string(check_encode(address_prefix + payload))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a Tezos address into its raw form.

        :param address: The Tezos address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - address_prefix: Address prefix (optional).
        :type kwargs: Any

        :return: The decoded raw bytes of the Tezos address.
        :rtype: str
        """

        if not kwargs.get("address_prefix"):
            address_prefix: bytes = cls.address_prefixes[Tezos.DEFAULT_ADDRESS_PREFIX]
        else:
            if kwargs.get("address_prefix") not in Tezos.ADDRESS_PREFIXES.get_address_prefixes():
                raise AddressError(
                    f"Invalid {cls.name()} address prefix",
                    expected=Tezos.ADDRESS_PREFIXES.get_address_prefixes(),
                    got=kwargs.get("address_prefix")
                )
            address_prefix: bytes = cls.address_prefixes[kwargs.get("address_prefix")]

        address_decode: bytes = check_decode(address)
        expected_length: int = len(address_prefix) + 20
        if len(address_decode) != expected_length:
            raise ValueError(f"Invalid length (expected: {expected_length}, got: {len(address_decode)})")

        prefix_got: bytes = address_decode[:len(address_prefix)]
        if address_prefix != prefix_got:
            raise ValueError(f"Invalid prefix (expected: {address_prefix}, got: {prefix_got})")

        return bytes_to_string(address_decode[len(address_prefix):])
