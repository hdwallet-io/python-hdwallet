#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import (
    ensure_string, check_encode
)
from ..consts import PUBLIC_KEY_TYPES
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..crypto import (
    hash160, sha256
)
from ..utils import (
    get_bytes, integer_to_bytes, bytes_to_string
)
from .p2sh import P2SHAddress


class P2WSHInP2SHAddress(P2SHAddress):

    @staticmethod
    def name() -> str:
        """
        Returns the name "P2WSH-In-P2SH".

        :return: The name of the address type.
        :rtype: str
        """

        return "P2WSH-In-P2SH"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a P2WSH address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - script_address_prefix: Script address prefix (optional).
            - public_key_type: Type of public key (optional).
            - alphabet: Custom alphabet for encoding (optional).
        :type kwargs: Any

        :return: The encoded P2WSH address.
        :rtype: str
        """

        script_address_prefix: bytes = integer_to_bytes(
            kwargs.get("script_address_prefix", cls.script_address_prefix)
        )
        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_bytes: bytes = (
            public_key.raw_compressed()
            if kwargs.get("public_key_type", PUBLIC_KEY_TYPES.COMPRESSED) == PUBLIC_KEY_TYPES.COMPRESSED else
            public_key.raw_uncompressed()
        )
        script_hash: bytes = hash160(get_bytes(
            "0020" + bytes_to_string(sha256(get_bytes(
                "5121" + bytes_to_string(public_key_bytes) + "51ae"
            )))
        ))

        return ensure_string(check_encode(
            (script_address_prefix + script_hash), alphabet=kwargs.get(
                "alphabet", cls.alphabet
            )
        ))
