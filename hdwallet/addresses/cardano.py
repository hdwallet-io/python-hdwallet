#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

import cbor2

from ..libs.base58 import (
    ensure_string, encode, decode
)
from ..libs.bech32 import (
    bech32_encode, bech32_decode
)
from ..eccs import (
    IPublicKey, KholawEd25519PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies.cardano import Cardano
from ..crypto import (
    chacha20_poly1305_encrypt, blake2b_224, sha3_256, crc32
)
from ..exceptions import (
    Error, AddressError
)
from ..utils import (
    get_bytes, bytes_to_integer, bytes_to_string, integer_to_bytes, path_to_indexes
)
from .iaddress import IAddress


class CardanoAddress(IAddress):

    address_types: dict = {
        "public-key": Cardano.PARAMS.PUBLIC_KEY_ADDRESS,
        "redemption": Cardano.PARAMS.REDEMPTION_ADDRESS
    }
    network_types: dict = {
        "mainnet": Cardano.NETWORKS.MAINNET.TYPE,
        "testnet": Cardano.NETWORKS.TESTNET.TYPE
    }
    prefix_types: dict = {
        "payment": Cardano.PARAMS.PAYMENT_PREFIX,
        "reward": Cardano.PARAMS.REWARD_PREFIX
    }
    payment_address_hrp: dict = {
        "mainnet": Cardano.NETWORKS.MAINNET.PAYMENT_ADDRESS_HRP,
        "testnet": Cardano.NETWORKS.TESTNET.PAYMENT_ADDRESS_HRP
    }
    reward_address_hrp: dict = {
        "mainnet": Cardano.NETWORKS.MAINNET.REWARD_ADDRESS_HRP,
        "testnet": Cardano.NETWORKS.TESTNET.REWARD_ADDRESS_HRP
    }
    chacha20_poly1305_associated_data: bytes = b""
    chacha20_poly1305_nonce: bytes = b"serokellfore"
    payload_tag: int = 24

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency associated with this address format.

        :return: The name of the cryptocurrency.
        :rtype: str
        """

        return "Cardano"

    @classmethod
    def encode(
        cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any
    ):
        """
        Encodes the given public key into a Cardano address based on the specified encoding type.

        :param public_key: The public key to encode. Can be bytes, string, or an object implementing IPublicKey.
        :type public_key: Union[bytes, str, IPublicKey]
        :param encode_type: The type of Cardano address encoding to use (default: Cardano.ADDRESS_TYPES.PAYMENT).
        :type encode_type: str
        :param kwargs: Additional keyword arguments specific to each encoding type.
        :type kwargs: Any

        :return: The encoded Cardano address as a string.
        :rtype: str
        """

        encode_type: str = kwargs.get("encode_type", Cardano.ADDRESS_TYPES.PAYMENT)

        if encode_type == Cardano.TYPES.BYRON_LEGACY:
            return cls.encode_byron_legacy(
                public_key=public_key,
                path=kwargs.get("path"),
                path_key=kwargs.get("path_key"),
                chain_code=kwargs.get("chain_code"),
                address_type=kwargs.get("address_type", Cardano.ADDRESS_TYPES.PUBLIC_KEY)
            )
        elif encode_type == Cardano.TYPES.BYRON_ICARUS:
            return cls.encode_byron_icarus(
                public_key=public_key,
                chain_code=kwargs.get("chain_code"),
                address_type=kwargs.get("address_type", Cardano.ADDRESS_TYPES.PUBLIC_KEY)
            )
        elif encode_type == Cardano.ADDRESS_TYPES.PAYMENT:
            return cls.encode_shelley(
                public_key=public_key,
                staking_public_key=kwargs.get("staking_public_key"),
                network=kwargs.get("network", "mainnet")
            )
        elif encode_type in [
            Cardano.ADDRESS_TYPES.STAKING, Cardano.ADDRESS_TYPES.REWARD
        ]:
            return cls.encode_shelley_staking(
                public_key=public_key,
                network=kwargs.get("network", "mainnet")
            )
        raise AddressError(
            "Invalid encode type", expected=[
                Cardano.TYPES.BYRON_LEGACY,
                Cardano.TYPES.BYRON_ICARUS,
                Cardano.ADDRESS_TYPES.PAYMENT,
                Cardano.ADDRESS_TYPES.STAKING,
                Cardano.ADDRESS_TYPES.REWARD
            ], got=encode_type
        )

    @classmethod
    def decode(
        cls, address: str, **kwargs: Any
    ) -> str:
        """
        Decodes the given Cardano address into its corresponding public key based on the specified decoding type.

        :param address: The Cardano address to decode.
        :type address: str
        :param decode_type: The type of Cardano address decoding to use (default: Cardano.ADDRESS_TYPES.PAYMENT).
        :type decode_type: str
        :param kwargs: Additional keyword arguments specific to each decoding type.
        :type kwargs: Any

        :return: The decoded public key as a string.
        :rtype: str
        """

        decode_type: str = kwargs.get("decode_type", Cardano.ADDRESS_TYPES.PAYMENT)

        if decode_type in [
            Cardano.TYPES.BYRON_LEGACY, Cardano.TYPES.BYRON_ICARUS
        ]:
            return cls.decode_byron(
                address=address, address_type=kwargs.get("address_type", Cardano.ADDRESS_TYPES.PUBLIC_KEY)
            )
        elif decode_type == Cardano.ADDRESS_TYPES.PAYMENT:
            return cls.decode_shelley(
                address=address, network=kwargs.get("network", "mainnet")
            )
        elif decode_type in [
            Cardano.ADDRESS_TYPES.STAKING, Cardano.ADDRESS_TYPES.REWARD
        ]:
            return cls.decode_shelley_staking(
                address=address, network=kwargs.get("network", "mainnet")
            )
        raise AddressError(
            "Invalid decode type", expected=[
                Cardano.TYPES.BYRON_LEGACY,
                Cardano.TYPES.BYRON_ICARUS,
                Cardano.ADDRESS_TYPES.PAYMENT,
                Cardano.ADDRESS_TYPES.STAKING,
                Cardano.ADDRESS_TYPES.REWARD
            ], got=decode_type
        )

    @classmethod
    def encode_byron(
        cls,
        public_key: IPublicKey,
        chain_code: Union[bytes, str],
        address_attributes: dict,
        address_type: str = Cardano.ADDRESS_TYPES.PUBLIC_KEY
    ) -> str:
        """
        Encodes the given public key and associated attributes into a Byron address format.

        :param public_key: The public key to encode.
        :type public_key: IPublicKey
        :param chain_code: The chain code associated with the address.
        :type chain_code: Union[bytes, str]
        :param address_attributes: Additional attributes to include in the address encoding.
        :type address_attributes: dict
        :param address_type: The type of Byron address to generate (default: Cardano.ADDRESS_TYPES.PUBLIC_KEY).
        :type address_type: str

        :return: The encoded Byron address as a string.
        :rtype: str
        """

        if address_type not in [
            Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
        ]:
            raise AddressError(
                "Invalid address type", expected=[
                    Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
                ], got=address_type
            )

        serialize: bytes = cbor2.dumps([
            cls.address_types[address_type],
            (cls.address_types[address_type], public_key.raw_compressed()[1:] + chain_code),
            address_attributes
        ])
        address_root_hash: bytes = blake2b_224(sha3_256(serialize))
        address_payload: bytes = cbor2.dumps([
            address_root_hash, address_attributes, cls.address_types[address_type]
        ])

        return ensure_string(encode(cbor2.dumps([
            cbor2.CBORTag(cls.payload_tag, address_payload),
            bytes_to_integer(crc32(address_payload))
        ])))

    @classmethod
    def encode_byron_icarus(
        cls,
        public_key: Union[bytes, str, IPublicKey],
        chain_code: Union[bytes, str],
        address_type: str = Cardano.ADDRESS_TYPES.PUBLIC_KEY
    ) -> str:
        """
        Encodes the given public key and associated attributes into a Byron Icarus address format.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param chain_code: The chain code associated with the address.
        :type chain_code: Union[bytes, str]
        :param address_type: The type of Byron address to generate (default: Cardano.ADDRESS_TYPES.PUBLIC_KEY).
        :type address_type: str

        :return: The encoded Byron Icarus address as a string.
        :rtype: str
        """

        if address_type not in [
            Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
        ]:
            raise AddressError(
                "Invalid address type", expected=[
                    Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
                ], got=address_type
            )

        chain_code: bytes = get_bytes(chain_code)
        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=KholawEd25519PublicKey
        )

        address_attributes: dict = { }
        return cls.encode_byron(
            public_key=public_key,
            chain_code=chain_code,
            address_attributes=address_attributes,
            address_type=address_type
        )

    @classmethod
    def encode_byron_legacy(
        cls,
        public_key: Union[bytes, str, IPublicKey],
        path: str,
        path_key: Union[bytes, str],
        chain_code: Union[bytes, str],
        address_type: str = Cardano.ADDRESS_TYPES.PUBLIC_KEY
    ) -> str:
        """
        Encodes the given public key and associated attributes into a Byron legacy address format.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param path: The hierarchical deterministic (HD) path for address derivation.
        :type path: str
        :param path_key: The HD path key used for encryption.
        :type path_key: Union[bytes, str]
        :param chain_code: The chain code associated with the address.
        :type chain_code: Union[bytes, str]
        :param address_type: The type of Byron address to generate (default: Cardano.ADDRESS_TYPES.PUBLIC_KEY).
        :type address_type: str

        :return: The encoded Byron legacy address as a string.
        :rtype: str
        """

        if address_type not in [
            Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
        ]:
            raise AddressError(
                "Invalid address type", expected=[
                    Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
                ], got=address_type
            )

        chain_code: bytes = get_bytes(chain_code)
        path_key: bytes = get_bytes(path_key)
        if len(path_key) != 32:
            raise Error("Invalid HD path key length", expected=32, got=len(path_key))

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=KholawEd25519PublicKey
        )

        plain_text: bytes = (
            integer_to_bytes(0x9F, bytes_num=1) +
            b"".join([cbor2.dumps(p) for p in path_to_indexes(path=path)]) +
            integer_to_bytes(0xFF, bytes_num=1)
        )

        cipher_text_bytes, tag_bytes = chacha20_poly1305_encrypt(
            key=path_key,
            nonce=cls.chacha20_poly1305_nonce,
            assoc_data=cls.chacha20_poly1305_associated_data,
            plain_text=plain_text
        )

        address_attributes: dict = {
            1: cbor2.dumps(cipher_text_bytes + tag_bytes)
        }
        return cls.encode_byron(
            public_key=public_key,
            chain_code=chain_code,
            address_attributes=address_attributes,
            address_type=address_type
        )

    @classmethod
    def decode_byron(cls, address: str, address_type: str = Cardano.ADDRESS_TYPES.PUBLIC_KEY) -> str:
        """
        Decodes the given Byron address into its corresponding public key.

        :param address: The Byron address to decode.
        :type address: str

        :param address_type: The type of Byron address (default: Cardano.ADDRESS_TYPES.PUBLIC_KEY).
        :type address_type: str

        :return: The decoded public key as a string.
        :rtype: str
        """

        if address_type not in [
            Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
        ]:
            raise AddressError(
                "Invalid address type", expected=[
                    Cardano.ADDRESS_TYPES.PUBLIC_KEY, Cardano.ADDRESS_TYPES.REDEMPTION
                ], got=address_type
            )

        try:
            address_decode: bytes = decode(address)
            address: Any = cbor2.loads(address_decode)
            if (len(address) != 2
                    or not isinstance(address[0], cbor2.CBORTag)
                    or not isinstance(address[1], int)):
                raise AddressError("Invalid address encoding")
            # Get and check CBOR tag
            cbor_tag = address[0]
            if cbor_tag.tag != cls.payload_tag:
                raise AddressError(f"Invalid CBOR tag ({cbor_tag.tag})")
            # Check CRC
            crc32_got = bytes_to_integer(crc32(cbor_tag.value))
            if crc32_got != address[1]:
                raise AddressError(f"Invalid CRC (expected: {address[1]}, got: {crc32_got})")

            address_payload: list = cbor2.loads(cbor_tag.value)
            if (len(address_payload) != 3
                    or not isinstance(address_payload[0], bytes)
                    or not isinstance(address_payload[1], dict)
                    or not isinstance(address_payload[2], int)):
                raise AddressError("Invalid address payload")
            # Check root hash length
            if len(address_payload[0]) != 28:
                raise AddressError("Invalid length", expected=28, got=len(address_payload[0]))
            # Check address attributes
            if len(address_payload[1]) > 2 or \
                    (len(address_payload[1]) != 0
                     and 1 not in address_payload[1]
                     and 2 not in address_payload[1]):
                raise AddressError("Invalid address attributes")
            # Check address type
            if address_payload[2] != cls.address_types[address_type]:
                raise AddressError(
                    "Invalid address type", expected=cls.address_types[address_type], got=address_payload[2]
                )

            address_attributes: tuple = (
                # hd path encrypted bytes
                cbor2.loads(address_payload[1][1]) if 1 in address_payload[1] else None,
                # network magic
                cbor2.loads(address_payload[1][2]) if 2 in address_payload[1] else None
            )
            return bytes_to_string(address_payload[0] + (
                address_attributes[0] if address_attributes[0] else b""
            ))
        except cbor2.CBORDecodeValueError as ex:
            raise AddressError("Invalid CBOR encoding") from ex

    @classmethod
    def decode_byron_icarus(cls, address: str, address_type: str = "public-key") -> str:
        """
        Decodes the given Byron Icarus address into its corresponding public key.

        :param address: The Byron Icarus address to decode.
        :type address: str

        :param address_type: The type of Byron address (default: "public-key").
        :type address_type: str

        :return: The decoded public key as a string.
        :rtype: str
        """

        return cls.decode_byron(address=address, address_type=address_type)

    @classmethod
    def decode_byron_legacy(cls, address: str, address_type: str = "public-key") -> str:
        """
        Decodes the given Byron Legacy address into its corresponding public key.

        :param address: The Byron Legacy address to decode.
        :type address: str

        :param address_type: The type of Byron address (default: "public-key").
        :type address_type: str

        :return: The decoded public key as a string.
        :rtype: str
        """

        return cls.decode_byron(address=address, address_type=address_type)

    @classmethod
    def encode_shelley(
        cls,
        public_key: Union[bytes, str, IPublicKey],
        staking_public_key: Union[bytes, str, IPublicKey],
        network: str = "mainnet"
    ) -> str:
        """
        Encodes the given public key and staking public key into a Shelley payment address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]

        :param staking_public_key: The staking public key to encode.
        :type staking_public_key: Union[bytes, str, IPublicKey]

        :param network: The network type (default: "mainnet").
        :type network: str

        :return: The encoded Shelley payment address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=KholawEd25519PublicKey
        )
        staking_public_key: IPublicKey = validate_and_get_public_key(
            public_key=staking_public_key, public_key_cls=KholawEd25519PublicKey
        )

        prefix: bytes = integer_to_bytes(
            (cls.prefix_types["payment"] << 4) + cls.network_types[network]
        )
        public_key_hash: bytes = blake2b_224(public_key.raw_compressed()[1:])
        staking_public_key_hash: bytes = blake2b_224(staking_public_key.raw_compressed()[1:])

        return bech32_encode(cls.payment_address_hrp[network], (
            prefix + public_key_hash + staking_public_key_hash
        ))

    @classmethod
    def decode_shelley(cls, address: str, network: str = "mainnet") -> str:
        """
        Decodes the given Shelley payment address into its corresponding public keys.

        :param address: The Shelley address to be decoded.
        :type address: str

        :param network: The network type (default: "mainnet").
        :type network: str

        :return: The decoded public keys.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            cls.payment_address_hrp[network], address
        )

        expected_length: int = (28 * 2) + 1
        if len(address_decode) != expected_length:
            raise AddressError("Invalid length", expected=expected_length, got=len(address_decode))

        prefix: bytes = integer_to_bytes(
            (cls.prefix_types["payment"] << 4) + cls.network_types[network]
        )
        prefix_got = address_decode[:len(prefix)]
        if prefix != prefix_got:
            raise AddressError("Invalid prefix", expected=prefix, got=prefix_got)

        return bytes_to_string(address_decode[len(prefix):])

    @classmethod
    def encode_shelley_staking(
        cls,
        public_key: Union[bytes, str, IPublicKey],
        network: str = "mainnet"
    ) -> str:
        """
        Encodes the given public key into a Shelley staking (reward) address.

        :param public_key: The public key to be encoded.
        :type public_key: Union[bytes, str, IPublicKey]

        :param network: The network type (default: "mainnet").
        :type network: str

        :return: The encoded Shelley staking address.
        :rtype: str
        """

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=KholawEd25519PublicKey
        )

        prefix: bytes = integer_to_bytes(
            (cls.prefix_types["reward"] << 4) + cls.network_types[network]
        )
        public_key_hash: bytes = blake2b_224(public_key.raw_compressed()[1:])

        return bech32_encode(cls.reward_address_hrp[network], (
            prefix + public_key_hash
        ))

    @classmethod
    def decode_shelley_staking(cls, address: str, network: str = "mainnet") -> str:
        """
        Decodes the given Shelley staking (reward) address into its corresponding public key.

        :param address: The Shelley staking address to be decoded.
        :type address: str

        :param network: The network type (default: "mainnet").
        :type network: str

        :return: The decoded public key.
        :rtype: str
        """

        hrp, address_decode = bech32_decode(
            cls.reward_address_hrp[network], address
        )

        expected_length: int = (28 * 1) + 1
        if len(address_decode) != expected_length:
            raise AddressError("Invalid length", expected=expected_length, got=len(address_decode))

        prefix: bytes = integer_to_bytes(
            (cls.prefix_types["reward"] << 4) + cls.network_types[network]
        )
        prefix_got = address_decode[:len(prefix)]
        if prefix != prefix_got:
            raise AddressError("Invalid prefix", expected=prefix, got=prefix_got)

        return bytes_to_string(address_decode[len(prefix):])
