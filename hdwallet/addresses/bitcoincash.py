#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Any, Union
)

from ..libs.base58 import ensure_string
from ..libs.bech32 import (
    CHARSET, convertbits
)
from ..consts import PUBLIC_KEY_TYPES
from ..eccs import (
    IPublicKey, SLIP10Secp256k1PublicKey, validate_and_get_public_key
)
from ..cryptocurrencies import BitcoinCash
from ..crypto import hash160
from ..utils import bytes_to_string
from .iaddress import IAddress


class BitcoinCashAddress(IAddress):

    hrp: str = BitcoinCash.NETWORKS.MAINNET.HRP
    public_key_address_prefix: int = BitcoinCash.NETWORKS.MAINNET.STD_PUBLIC_KEY_ADDRESS_PREFIX
    script_address_prefix: int = BitcoinCash.NETWORKS.MAINNET.STD_SCRIPT_ADDRESS_PREFIX

    @staticmethod
    def name() -> str:
        """
        Returns the name of the cryptocurrency.

        :return: The name of the address type.
        :rtype: str
        """
        return "BitcoinCash"

    @classmethod
    def encode(cls, public_key: Union[bytes, str, IPublicKey], **kwargs: Any) -> str:
        """
        Encode a public key into a Bitcoin Cash CashAddr address.

        :param public_key: The public key to encode.
        :type public_key: Union[bytes, str, IPublicKey]
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
            - public_key_type: Type of the public key (optional).
            - public_key_address_prefix: Address prefix for P2PKH (optional).
            - script_address_prefix: Address prefix for P2SH (optional).
        :type kwargs: Any

        :return: The encoded CashAddr address.
        :rtype: str
        """
        hrp = kwargs.get("hrp", cls.hrp)
        public_key_address_prefix = kwargs.get("public_key_address_prefix", cls.public_key_address_prefix)

        public_key: IPublicKey = validate_and_get_public_key(
            public_key=public_key, public_key_cls=SLIP10Secp256k1PublicKey
        )
        public_key_hash: bytes = hash160(
            public_key.raw_compressed()
            if kwargs.get("public_key_type", PUBLIC_KEY_TYPES.COMPRESSED) == PUBLIC_KEY_TYPES.COMPRESSED else
            public_key.raw_uncompressed()
        )

        # CashAddr version byte: 0 for P2PKH, 1 for P2SH
        version_byte = 0x00  # P2PKH with 160-bit hash

        # Pack version and hash
        payload = bytes([version_byte]) + public_key_hash

        # Convert to 5-bit groups
        data = convertbits(payload, 8, 5)

        # CashAddr polymod for checksum
        generator = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
        hrp_expand = [ord(x) & 0x1f for x in hrp] + [0]
        values = hrp_expand + data + [0, 0, 0, 0, 0, 0, 0, 0]

        chk = 1
        for value in values:
            top = chk >> 35
            chk = ((chk & 0x07ffffffff) << 5) ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        polymod = chk ^ 1

        # Create checksum
        checksum = [(polymod >> (5 * (7 - i))) & 0x1f for i in range(8)]

        # Encode as CashAddr
        combined = data + checksum
        return ensure_string(hrp + ':' + ''.join([CHARSET[d] for d in combined]))

    @classmethod
    def decode(cls, address: str, **kwargs: Any) -> str:
        """
        Decode a Bitcoin Cash CashAddr address.

        :param address: The CashAddr address to decode.
        :type address: str
        :param kwargs: Additional keyword arguments.
            - hrp: Human-readable part (optional).
        :type kwargs: Any

        :return: The decoded address as a string.
        :rtype: str
        """
        hrp_expected = kwargs.get("hrp", cls.hrp)

        # Parse address
        if ':' in address:
            hrp, addr = address.split(':', 1)
        else:
            hrp = None
            addr = address

        if not all(x in CHARSET for x in addr.lower()):
            raise ValueError("Invalid CashAddr characters")

        addr = addr.lower()
        data = [CHARSET.find(x) for x in addr]

        # Verify checksum
        if hrp:
            generator = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
            hrp_expand = [ord(x) & 0x1f for x in hrp.lower()] + [0]
            values = hrp_expand + data

            chk = 1
            for value in values:
                top = chk >> 35
                chk = ((chk & 0x07ffffffff) << 5) ^ value
                for i in range(5):
                    chk ^= generator[i] if ((top >> i) & 1) else 0
            polymod = chk ^ 1

            if polymod != 0:
                raise ValueError("Invalid CashAddr checksum")

        if hrp and hrp != hrp_expected:
            raise ValueError(f"Invalid HRP (expected: {hrp_expected}, got: {hrp})")

        # Remove 8-byte checksum
        data = data[:-8]

        # Convert from 5-bit to 8-bit
        decoded = convertbits(data, 5, 8, False)
        if decoded is None or len(decoded) < 21:
            raise ValueError("Invalid CashAddr data")

        # First byte is version, rest is hash
        version = decoded[0]
        address_hash = bytes(decoded[1:])

        return bytes_to_string(address_hash)
