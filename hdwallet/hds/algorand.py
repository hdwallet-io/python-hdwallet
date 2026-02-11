#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union
)

import hmac
import hashlib

from ..eccs import KholawEd25519ECC
from ..addresses import AlgorandAddress
from ..cryptocurrencies import Algorand
from ..seeds import ISeed
from ..exceptions import (
    Error, SeedError, DerivationError
)
from ..utils import (
    get_bytes, bytes_to_integer, integer_to_bytes
)
from .bip32 import BIP32HD


class AlgorandHD(BIP32HD):

    def __init__(self) -> None:
        """
        Initialize a AlgorandHD instance.
        """

        super(AlgorandHD, self).__init__(
            ecc=KholawEd25519ECC
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the Algorand class.

        :return: The name of the Algorand class.
        :rtype: str
        """
        return "Algorand"

    def from_seed(self, seed: Union[bytes, str, ISeed], **kwargs) -> "AlgorandHD":
        """
        Initializes the AlgorandHD instance from the given seed.

        :param seed: The seed to initialize the instance. It can be of type `bytes`, `str`, or `ISeed`.
        :type seed: Union[bytes, str, ISeed]
        :param kwargs: Additional keyword arguments.

        :return: The initialized AlgorandHD instance.
        :rtype: AlgorandHD
        """

        try:
            self._seed = get_bytes(
                seed.seed() if isinstance(seed, ISeed) else seed
            )
        except ValueError as error:
            raise SeedError("Invalid seed data") from error

        if len(self._seed) < 16:
            raise Error("Invalid seed length", expected="< 16", got=len(self._seed))

        def clamp_kL(kL: bytearray):
            kL[0] &= 0b11111000
            kL[31] &= 0b01111111
            kL[31] |= 0b01000000
            return kL

        k = hashlib.sha512(self._seed).digest()
        kL = bytearray(k[0:32])
        kR = k[32:64]

        while (kL[31] & 0b00100000) != 0:
            k = hmac.new(kL, kR, hashlib.sha512).digest()
            kL = bytearray(k[0:32])
            kR = k[32:64]

        kL = clamp_kL(kL)

        chain_code_bytes = hashlib.sha256(bytes([0x01]) + self._seed).digest()

        self._root_private_key = self._ecc.PRIVATE_KEY.from_bytes(bytes(kL + kR))
        self._root_chain_code = chain_code_bytes

        self._private_key, self._chain_code, self._parent_fingerprint = (
            self._root_private_key, self._root_chain_code, (integer_to_bytes(0x00) * 4)
        )
        self._root_public_key = self._root_private_key.public_key()
        self._public_key = self._root_public_key
        self._strict = True
        self.__update__()
        return self

    def drive(self, index: int) -> Optional["AlgorandHD"]:
        """
        Drives the AlgorandHD instance forward along the derivation path by deriving a child key at the given index.

        :param index: The index to derive the child key.
        :type index: int

        :return: The updated AlgorandHD instance with the derived child key, or None if the derivation fails.
        :rtype: Optional[AlgorandHD]
        """

        G = 9  # Peikert's suggestion for 8 levels of derivation security
        index_bytes = integer_to_bytes(index, 4, endianness="little")
        cc = self._chain_code

        if cc is None:
            raise DerivationError("Chain code is not set")

        # Hardened derivation requires private key
        if index & 0x80000000:
            if self._private_key is None:
                raise DerivationError("Private key required for hardened derivation")

            kL = self._private_key.raw()[:32]
            kR = self._private_key.raw()[32:]

            data = bytes([0x00]) + kL + kR + index_bytes
            z = hmac.new(cc, data, hashlib.sha512).digest()
            data = bytes([0x01]) + kL + kR + index_bytes
            child_cc = hmac.new(cc, data, hashlib.sha512).digest()[32:]

            zL, zR = z[:32], z[32:]

            def trunc_256_minus_g_bits(buf: bytes, g: int) -> bytes:
                if g < 0 or g > 256:
                    raise ValueError("g must be between 0 and 256")
                out = bytearray(buf)
                remaining = g
                for i in range(len(out) - 1, -1, -1):
                    if remaining >= 8:
                        out[i] = 0
                        remaining -= 8
                    elif remaining > 0:
                        out[i] &= (0xFF >> remaining)
                        break
                return bytes(out)

            truncated_zL = trunc_256_minus_g_bits(zL, G)
            kL_int = bytes_to_integer(kL, endianness="little")
            zL_int = bytes_to_integer(truncated_zL, endianness="little")
            child_kL_int = kL_int + (8 * zL_int)

            if child_kL_int >= 2 ** 255:
                raise DerivationError("zL * 8 + kL exceeds Ed25519 scalar limit")

            child_kL = integer_to_bytes(child_kL_int, 32, endianness="little")
            child_kR = integer_to_bytes(
                (bytes_to_integer(kR, "little") + bytes_to_integer(zR, "little")) % (2 ** 256),
                32, "little"
            )

            child_key = self._ecc.PRIVATE_KEY.from_bytes(child_kL + child_kR)
            self._private_key = child_key
            self._parent_fingerprint = get_bytes(self.fingerprint())
            self._public_key = child_key.public_key()

        # Non-hardened derivation (public key supported)
        else:
            if self._public_key is None:
                raise DerivationError("Public key is required for non-hardened derivation")

            A = self._public_key.raw_compressed()[1:]
            data = bytes([0x02]) + A + index_bytes
            z = hmac.new(cc, data, hashlib.sha512).digest()
            data = bytes([0x03]) + A + index_bytes
            child_cc = hmac.new(cc, data, hashlib.sha512).digest()[32:]

            zL = z[:32]

            def trunc_256_minus_g_bits(buf: bytes, g: int) -> bytes:
                if g < 0 or g > 256:
                    raise ValueError("g must be between 0 and 256")
                out = bytearray(buf)
                remaining = g
                for i in range(len(out) - 1, -1, -1):
                    if remaining >= 8:
                        out[i] = 0
                        remaining -= 8
                    elif remaining > 0:
                        out[i] &= (0xFF >> remaining)
                        break
                return bytes(out)

            truncated_zL = trunc_256_minus_g_bits(zL, G)
            scalar = 8 * bytes_to_integer(truncated_zL, "little")
            new_point = self._public_key.point() + (self._ecc.GENERATOR * scalar)
            self._parent_fingerprint = get_bytes(self.fingerprint())
            self._public_key = self._ecc.PUBLIC_KEY.from_point(new_point)

        self._chain_code = child_cc
        self._depth += 1
        self._index = index
        self._fingerprint = get_bytes(self.fingerprint())

        return self

    def root_xprivate_key(
        self, version: Union[bytes, int] = Algorand.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the root extended private key (xprv) in serialized format.

        :param version: The version bytes for the extended key. Defaults to Algorand mainnet P2PKH version.
        :type version: Union[bytes, int]
        :param encoded: Whether to return the key in encoded format. Defaults to True.
        :type encoded: bool

        :return: The root extended private key (xprv) in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """
        return super(AlgorandHD, self).root_xprivate_key(version=version, encoded=encoded)

    def xprivate_key(
        self, version: Union[bytes, int] = Algorand.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Retrieves the extended private key (xprivate key) as a serialized string.

        :param version: The version bytes or integer version of the xprivate key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded.
        :type encoded: bool

        :return: The serialized xprivate key as a string, or None if the private key or chain code is not set.
        :rtype: Optional[str]
        """
        return super(AlgorandHD, self).xprivate_key(version=version, encoded=encoded)

    def address(self, **kwargs) -> str:
        """
        Generates a Algorand address using the AlgorandAddress encoding scheme.

        :param kwargs: Additional keyword arguments for encoding.

        :return: Algorand address encoded.
        :rtype: str
        """

        return AlgorandAddress.encode(public_key=self._public_key)
