#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import ensure_string
from ..libs.segwit_bech32 import (
    segwit_encode
)
from ..consts import PUBLIC_KEY_TYPES
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Bitcoin
from ..crypto import sha256
from ..utils import (
    get_bytes, bytes_to_string
)
from .p2wpkh import P2WPKHAddress


class P2WSHAddress(P2WPKHAddress):

    witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WSH

    @staticmethod
    def name() -> str:
        """
        Return the name of the address type, which is "P2WSH".

        :return: The name of the address type.
        :rtype: str
        """

        return "P2WSH"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a P2TR address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - public_key_type: Type of the public key (compressed or uncompressed).
            - hrp: Human-readable part (optional).
            - version: Address version (optional).
        :type kwargs: Any

        :return: The encoded P2TR address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_bytes: bytes = (
            public_key.raw_compressed()
            if kwargs.get("public_key_type", PUBLIC_KEY_TYPES.COMPRESSED) == PUBLIC_KEY_TYPES.COMPRESSED else
            public_key.raw_uncompressed()
        )
        script_hash: bytes = sha256(get_bytes(
            "5121" + bytes_to_string(public_key_bytes) + "51ae"
        ))
        return ensure_string(segwit_encode(
            kwargs.get("hrp", cls.hrp), kwargs.get("version", cls.witness_version), script_hash
        ))
