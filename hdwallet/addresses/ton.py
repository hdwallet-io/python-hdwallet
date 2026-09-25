#!/usr/bin/env python3

# Copyright © 2020-2026, Abenezer Lulseged Wube <itsm3abena@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

import base64

from ..eccs import (
    IPublicKey, SLIP10Ed25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Ton
from ..crypto import crc16_ccitt
from ..libs.ton.wallet import wallet_v4r2_address_hash, wallet_v5r1_address_hash
from ..utils import (
    bytes_to_string
)
from .iaddress import IAddress


class TonAddress(IAddress):

    bounceable_tag: int = Ton.PARAMS.BOUNCEABLE_TAG
    non_bounceable_tag: int = Ton.PARAMS.NON_BOUNCEABLE_TAG
    test_flag: int = Ton.PARAMS.TEST_FLAG

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Ton"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encodes a public key into a TON user-friendly address (Wallet V5R1 by default).

        :param public_key: The public key to encode. Can be of type bytes, str, or IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional arguments such as bounceable, testnet, wallet_version,
            wallet_id, network_global_id, subwallet_number, and workchain.
        :type kwargs: Any

        :return: The encoded TON address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Ed25519PublicKey
        )
        bounceable: bool = kwargs.get("bounceable", Ton.PARAMS.DEFAULT_BOUNCEABLE)
        testnet: bool = kwargs.get("testnet", False)
        workchain: int = kwargs.get("workchain", Ton.PARAMS.WORKCHAIN)
        wallet_version: str = kwargs.get("wallet_version", Ton.PARAMS.DEFAULT_WALLET_VERSION)
        public_key_bytes: bytes = public_key.raw_compressed()[1:]

        if wallet_version == "v4r2":
            wallet_id: int = kwargs.get("wallet_id", Ton.PARAMS.WALLET_ID)
            address_hash: bytes = wallet_v4r2_address_hash(
                public_key=public_key_bytes,
                workchain=workchain,
                wallet_id=wallet_id
            )
        elif wallet_version == "v5r1":
            network_global_id: int = kwargs.get(
                "network_global_id",
                Ton.PARAMS.TESTNET_NETWORK_GLOBAL_ID if testnet else Ton.PARAMS.MAINNET_NETWORK_GLOBAL_ID
            )
            address_hash = wallet_v5r1_address_hash(
                public_key=public_key_bytes,
                workchain=workchain,
                network_global_id=network_global_id,
                subwallet_number=kwargs.get("subwallet_number", Ton.PARAMS.SUBWALLET_NUMBER),
                wallet_id=kwargs.get("wallet_id")
            )
        else:
            raise ValueError(f"Unsupported wallet version (got: {wallet_version})")
        return cls._encode_friendly_address(
            address_hash=address_hash,
            workchain=workchain,
            bounceable=bounceable,
            testnet=testnet
        )

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decodes a TON user-friendly address into its raw account hash.

        :param address: The TON address to decode.
        :type address: str
        :param kwargs: Additional arguments.
        :type kwargs: Any

        :return: The decoded account hash in its raw form.
        :rtype: str
        """

        parsed_address = cls._decode_friendly_address(address=address)
        return bytes_to_string(parsed_address["hash_part"])

    @classmethod
    def _encode_friendly_address(
        cls,
        address_hash: bytes,
        workchain: int,
        bounceable: bool,
        testnet: bool
    ) -> str:
        tag = cls.bounceable_tag if bounceable else cls.non_bounceable_tag
        if testnet:
            tag |= cls.test_flag

        payload = bytes([tag, workchain & 0xFF]) + address_hash
        checksum = crc16_ccitt(payload)
        encoded = base64.b64encode(payload + checksum).decode("utf-8")
        return encoded.replace("+", "-").replace("/", "_")

    @classmethod
    def _decode_friendly_address(cls, address: str) -> dict:
        if len(address) != 48:
            raise ValueError(f"Invalid length (expected: 48, got: {len(address)})")

        normalized_address = address.replace("-", "+").replace("_", "/")
        data = base64.b64decode(normalized_address + "==")
        if len(data) != 36:
            raise ValueError(f"Invalid address payload length (expected: 36, got: {len(data)})")

        payload, checksum = data[:34], data[34:36]
        calculated_checksum = crc16_ccitt(payload)
        if checksum != calculated_checksum:
            raise ValueError("Invalid address checksum")

        tag = payload[0]
        is_test_only = bool(tag & cls.test_flag)
        tag ^= cls.test_flag if is_test_only else 0
        if tag not in (cls.bounceable_tag, cls.non_bounceable_tag):
            raise ValueError(f"Invalid address tag (got: {hex(tag)})")

        workchain = -1 if payload[1] == 0xFF else payload[1]
        if workchain not in (0, -1):
            raise ValueError(f"Invalid workchain (got: {workchain})")

        return {
            "is_test_only": is_test_only,
            "is_bounceable": tag == cls.bounceable_tag,
            "workchain": workchain,
            "hash_part": payload[2:34]
        }
