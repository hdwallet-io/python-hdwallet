#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Tuple, Union, Optional, Dict
)

from ..libs.base58 import (
    encode_monero, decode_monero
)
from ..eccs import (
    IPublicKey, SLIP10Ed25519MoneroPublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import Monero
from ..crypto import kekkak256
from ..exceptions import (
    Error, AddressError
)
from ..utils import (
    bytes_to_string, integer_to_bytes
)


class MoneroAddress:

    checksum_length: int = Monero.PARAMS.CHECKSUM_LENGTH
    payment_id_length: int = Monero.PARAMS.PAYMENT_ID_LENGTH
    networks: Dict[str, Dict[str, Dict[str, int]]] = {
        "mainnet": {
            "address_types": {
                "standard": Monero.NETWORKS.MAINNET.STANDARD,
                "integrated": Monero.NETWORKS.MAINNET.INTEGRATED,
                "sub-address": Monero.NETWORKS.MAINNET.SUB_ADDRESS
            }
        },
        "stagenet": {
            "address_types": {
                "standard": Monero.NETWORKS.STAGENET.STANDARD,
                "integrated": Monero.NETWORKS.STAGENET.INTEGRATED,
                "sub-address": Monero.NETWORKS.STAGENET.SUB_ADDRESS
            }
        },
        "testnet": {
            "address_types": {
                "standard": Monero.NETWORKS.TESTNET.STANDARD,
                "integrated": Monero.NETWORKS.TESTNET.INTEGRATED,
                "sub-address": Monero.NETWORKS.TESTNET.SUB_ADDRESS
            }
        }
    }

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency, which is "Monero".

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Monero"

    @classmethod
    def compute_checksum(cls, public_key: bytes) -> bytes:
        return kekkak256(public_key)[:cls.checksum_length]

    @classmethod
    def encode(
        cls,
        spend_public_key: Union[bytes, str, IPublicKey],
        view_public_key: Union[bytes, str, IPublicKey],
        network: str = "mainnet",
        address_type: str = Monero.ADDRESS_TYPES.STANDARD,
        payment_id: Optional[bytes] = None
    ) -> str:
        """
        Encodes the given spend and view public keys into a Monero address.

        :param spend_public_key: The spend public key.
        :type spend_public_key: Union[bytes, str, IPublicKey]
        :param view_public_key: The view public key.
        :type view_public_key: Union[bytes, str, IPublicKey]
        :param network: The network (default is "mainnet").
        :type network: str
        :param address_type: The address type (default is Monero.ADDRESS_TYPES.STANDARD).
        :type address_type: str
        :param payment_id: Optional payment ID bytes.
        :type payment_id: Optional[bytes]

        :return: The encoded Monero address.
        :rtype: str
        """

        spend_public_key: IPublicKey = validate_and_get_public_key(
            public_key=spend_public_key, public_key_cls=SLIP10Ed25519MoneroPublicKey
        )
        view_public_key: IPublicKey = validate_and_get_public_key(
            public_key=view_public_key, public_key_cls=SLIP10Ed25519MoneroPublicKey
        )

        if payment_id is not None and len(payment_id) != cls.payment_id_length:
            raise Error("Invalid payment ID length")

        version: bytes = integer_to_bytes(
            cls.networks[network]["address_types"][address_type]
        )
        payload: bytes = (
            version + spend_public_key.raw_compressed() +
            view_public_key.raw_compressed() +
            (b"" if payment_id is None else payment_id)
        )

        return encode_monero(payload + cls.compute_checksum(payload))

    @classmethod
    def decode(
        cls,
        address: str,
        network: str = "mainnet",
        address_type: str = Monero.ADDRESS_TYPES.STANDARD,
        payment_id: Optional[bytes] = None
    ) -> Tuple[str, str]:
        """
        Decodes a Monero address into spend and view public keys.

        :param address: The Monero address to decode.
        :type address: str
        :param network: The network (default is "mainnet").
        :type network: str
        :param address_type: The address type (default is Monero.ADDRESS_TYPES.STANDARD).
        :type address_type: str
        :param payment_id: Optional payment ID bytes.
        :type payment_id: Optional[bytes]

        :return: A tuple containing the spend public key and view public key.
        :rtype: Tuple[str, str]
        """

        address_decode: bytes = decode_monero(address)

        checksum: bytes = address_decode[-1 * cls.checksum_length:]
        payload_with_prefix: bytes = address_decode[:-1 * cls.checksum_length]

        checksum_got: bytes = cls.compute_checksum(payload_with_prefix)
        if checksum != checksum_got:
            raise AddressError(
                "Invalid checksum", expected=bytes_to_string(checksum), got=bytes_to_string(checksum_got)
            )

        version: bytes = integer_to_bytes(
            cls.networks[network]["address_types"][address_type]
        )
        version_got = payload_with_prefix[:len(version)]
        if version != version_got:
            raise AddressError(
                "Invalid version", expected=version, got=version_got
            )

        payload_without_prefix: bytes = payload_with_prefix[len(version):]

        expected_length: int = SLIP10Ed25519MoneroPublicKey.compressed_length() * 2
        try:
            if len(payload_without_prefix) != expected_length:
                raise AddressError(
                    "Invalid length", expected=expected_length, got=len(payload_without_prefix)
                )
        except ValueError as ex:
            if len(payload_without_prefix) != expected_length + cls.payment_id_length:
                raise AddressError(
                    "Invalid length",
                    expected=(expected_length + cls.payment_id_length),
                    got=len(payload_without_prefix)
                ) from ex

            if payment_id is None or len(payment_id) != cls.payment_id_length:
                raise Error("Invalid payment ID") from ex

            payment_id_got_bytes = payload_without_prefix[-cls.payment_id_length:]
            if payment_id != payment_id_got_bytes:
                raise Error(
                    "Invalid payment ID",
                    expected=bytes_to_string(payment_id_got_bytes),
                    got=bytes_to_string(payment_id_got_bytes)
                ) from ex

        length: int = SLIP10Ed25519MoneroPublicKey.compressed_length()

        spend_public_key: bytes = payload_without_prefix[:length]
        if not SLIP10Ed25519MoneroPublicKey.is_valid_bytes(spend_public_key):
            raise Error(f"Invalid {SLIP10Ed25519MoneroPublicKey.name()} public key {bytes_to_string(spend_public_key)}")

        view_public_key: bytes = payload_without_prefix[length:(length * 2)]
        if not SLIP10Ed25519MoneroPublicKey.is_valid_bytes(view_public_key):
            raise Error(f"Invalid {SLIP10Ed25519MoneroPublicKey.name()} public key {bytes_to_string(view_public_key)}")

        return bytes_to_string(spend_public_key), bytes_to_string(view_public_key)
