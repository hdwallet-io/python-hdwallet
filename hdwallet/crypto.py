#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union, Tuple
)
from Crypto.Hash import (
    SHA512, SHA3_256, keccak
)
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2

import binascii
import crcmod.predefined
import hashlib
import hmac

from .libs.ripemd160 import ripemd160 as r160
from .consts import SLIP10_SECP256K1_CONST
from .utils import (
    get_bytes, encode, integer_to_bytes
)


def hmac_sha256(key: Union[bytes, str], data: Union[bytes, str]) -> bytes:
    """
    Generate an HMAC-SHA256 hash of the given data using the provided key.

    :param key: The key for the HMAC algorithm, as bytes or a string.
    :type key: Union[bytes, str]
    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]

    :return: The resulting HMAC-SHA256 hash as bytes.
    :rtype: bytes
    """

    if hasattr(hmac, "digest"):
        return hmac.digest(
            encode(key), encode(data), "sha256"
        )
    return hmac.new(
        encode(key), encode(data), hashlib.sha256
    ).digest()


def hmac_sha512(key: Union[bytes, str], data: Union[bytes, str]) -> bytes:
    """
    Generate an HMAC-SHA512 hash of the given data using the provided key.

    :param key: The key for the HMAC algorithm, as bytes or a string.
    :type key: Union[bytes, str]
    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]

    :return: The resulting HMAC-SHA512 hash as bytes.
    :rtype: bytes
    """

    if hasattr(hmac, "digest"):
        return hmac.digest(
            encode(key), encode(data), "sha512"
        )
    return hmac.new(
        encode(key), encode(data), hashlib.sha512
    ).digest()


def blake2b(data: Union[bytes, str], digest_size: int, key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param digest_size: The size of the resulting digest in bytes.
    :type digest_size: int
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return hashlib.blake2b(
        encode(data), digest_size=digest_size, key=encode(key), salt=encode(salt)
    ).digest()


def blake2b_32(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 32-byte BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 32-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=4, key=key, salt=salt)


def blake2b_40(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 40-byte BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 40-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=5, key=key, salt=salt)


def blake2b_160(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 160-bit (20-byte) BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 20-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=20, key=key, salt=salt)


def blake2b_224(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 224-bit (28-byte) BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 28-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=28, key=key, salt=salt)


def blake2b_256(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 256-bit (32-byte) BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 32-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=32, key=key, salt=salt)


def blake2b_512(data: Union[bytes, str], key: Union[bytes, str] = b"", salt: Union[bytes, str] = b"") -> bytes:
    """
    Generate a 512-bit (64-byte) BLAKE2b hash of the given data with optional key and salt.

    :param data: The data to be hashed, as bytes or a string.
    :type data: Union[bytes, str]
    :param key: Optional key for keyed hashing, as bytes or a string. Default is an empty byte string.
    :type key: Union[bytes, str]
    :param salt: Optional salt for added randomness, as bytes or a string. Default is an empty byte string.
    :type salt: Union[bytes, str], optional

    :return: The resulting 64-byte BLAKE2b hash as bytes.
    :rtype: bytes
    """

    return blake2b(data=data, digest_size=64, key=key, salt=salt)


def chacha20_poly1305_encrypt(
    key: Union[bytes, str], nonce: Union[bytes, str], assoc_data: Union[bytes, str], plain_text: Union[bytes, str]
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using ChaCha20-Poly1305 AEAD cipher.

    :param key: The encryption key, as bytes or a string.
    :type key: Union[bytes, str]
    :param nonce: The nonce value, as bytes or a string.
    :type nonce: Union[bytes, str]
    :param assoc_data: The associated data to authenticate, as bytes or a string.
    :type assoc_data: Union[bytes, str]
    :param plain_text: The plaintext data to be encrypted, as bytes or a string.
    :type plain_text: Union[bytes, str]

    :return: A tuple containing the encrypted data and the authentication tag.
    :rtype: Tuple[bytes, bytes]
    """

    cipher: ChaCha20_Poly1305 = ChaCha20_Poly1305.new(
        key=encode(key), nonce=encode(nonce)
    )
    cipher.update(encode(assoc_data))
    return cipher.encrypt_and_digest(encode(plain_text))


def chacha20_poly1305_decrypt(
    key: Union[bytes, str], nonce: Union[bytes, str], assoc_data: Union[bytes, str], cipher_text: Union[bytes, str], tag: Union[bytes, str]
) -> bytes:
    """
    Decrypt data using ChaCha20-Poly1305 AEAD cipher.

    :param key: The decryption key, as bytes or a string.
    :type key: Union[bytes, str]
    :param nonce: The nonce value, as bytes or a string.
    :type nonce: Union[bytes, str]
    :param assoc_data: The associated data used during encryption, as bytes or a string.
    :type assoc_data: Union[bytes, str]
    :param cipher_text: The encrypted data to be decrypted, as bytes or a string.
    :type cipher_text: Union[bytes, str]
    :param tag: The authentication tag associated with the encrypted data, as bytes or a string.
    :type tag: Union[bytes, str]

    :return: The decrypted plaintext data.
    :rtype: bytes
    """

    cipher: ChaCha20_Poly1305 = ChaCha20_Poly1305.new(
        key=encode(key), nonce=encode(nonce)
    )
    cipher.update(encode(assoc_data))
    return cipher.decrypt_and_verify(encode(cipher_text), encode(tag))


def sha256(data: Union[str, bytes]) -> bytes:
    """
    Calculate the SHA-256 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The SHA-256 hash digest as bytes.
    :rtype: bytes
    """

    return hashlib.sha256(get_bytes(data)).digest()


def double_sha256(data: Union[str, bytes]) -> bytes:
    """
    Calculate the double SHA-256 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The double SHA-256 hash digest as bytes.
    :rtype: bytes
    """

    return hashlib.sha256(sha256(data)).digest()


def hash160(data: Union[str, bytes]) -> bytes:
    """
    Calculate the HASH160 hash (RIPEMD-160 of SHA-256) of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The HASH160 hash digest as bytes.
    :rtype: bytes
    """

    return ripemd160(sha256(data))


def crc32(data: Union[bytes, str]) -> bytes:
    """
    Calculate the CRC-32 checksum of the given data.

    :param data: The data to calculate the CRC-32 checksum for, as bytes or a string.
    :type data: Union[bytes, str]

    :return: The CRC-32 checksum as a 4-byte bytes object.
    :rtype: bytes
    """

    return integer_to_bytes(
        binascii.crc32(encode(data)), bytes_num=4
    )


def crc16_ccitt(data: Union[bytes, str]) -> bytes:
    """
    Calculate the CRC-16-CCITT checksum of the given data.

    :param data: The data to calculate the CRC-16-CCITT checksum for, as bytes or a string.
    :type data: Union[bytes, str]

    :return: The CRC-16-CCITT checksum as a 2-byte bytes object.
    :rtype: bytes
    """

    poly = 0x1021
    reg = 0
    message = encode(data) + b"\x00\x00"

    for byte in message:
        mask = 0x80
        while mask > 0:
            reg <<= 1
            if byte & mask:
                reg += 1
            mask >>= 1
            if reg > 0xFFFF:
                reg &= 0xFFFF
                reg ^= poly

    return bytes([(reg >> 8) & 0xFF, reg & 0xFF])


def xmodem_crc(data: Union[bytes, str]) -> bytes:
    """
    Calculate the XMODEM CRC checksum of the given data.

    :param data: The data to calculate the XMODEM CRC checksum for, as bytes or a string.
    :type data: Union[bytes, str]

    :return: The XMODEM CRC checksum as a bytes object.
    :rtype: bytes
    """

    xmodem = crcmod.predefined.Crc("xmodem")
    return xmodem.new(encode(data)).digest()


def pbkdf2_hmac_sha512(
    password: Union[bytes, str], salt: Union[bytes, str], iteration_num: int, derived_key_length: Optional[int] = None
) -> bytes:
    """
    Derive a key using PBKDF2-HMAC-SHA512.

    :param password: The password to derive the key from, as bytes or a string.
    :type password: Union[bytes, str]
    :param salt: The salt value used in the key derivation process, as bytes or a string.
    :type salt: Union[bytes, str]
    :param iteration_num: The number of iterations of the HMAC-SHA512 hashing to apply.
    :type iteration_num: int
    :param derived_key_length: Optional. The desired length of the derived key in bytes.
                               If not provided, it defaults to SHA-512 digest size.
    :type derived_key_length: Optional[int]

    :return: The derived key as bytes.
    :rtype: bytes
    """

    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha512", encode(password), encode(salt), iteration_num, derived_key_length)
    return PBKDF2(
        password, encode(salt), derived_key_length or SHA512.digest_size, count=iteration_num, hmac_hash_module=SHA512
    )


def keccak256(data: Union[str, bytes]) -> bytes:
    """
    Calculate the Keccak-256 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The Keccak-256 hash digest as bytes.
    :rtype: bytes
    """

    return keccak.new(data=encode(data), digest_bits=256).digest()


# Backward compatibility alias of the previously misspelled name
kekkak256 = keccak256


def ripemd160(data: Union[str, bytes]) -> bytes:
    """
    Calculate the RIPEMD-160 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The RIPEMD-160 hash digest as bytes.
    :rtype: bytes
    """

    if "ripemd160" in hashlib.algorithms_available:
        hashlib.new("ripemd160", get_bytes(data)).digest()
    return r160(get_bytes(data))


def get_checksum(data: Union[str, bytes]) -> bytes:
    """
    Calculate the checksum for the given raw bytes.

    The checksum is derived by performing a double SHA-256 hash on the input
    and returning the first few bytes, as determined by `CHECKSUM_BYTE_LENGTH`.

    :param data: The raw data to checksum.
    :type data: Union[str, bytes]

    :returns: The checksum of the data.
    :rtype: bytes
    """

    return double_sha256(data)[:SLIP10_SECP256K1_CONST.CHECKSUM_BYTE_LENGTH]


def sha512(data: Union[str, bytes]) -> bytes:
    """
    Calculate the SHA-512 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The SHA-512 hash digest as bytes.
    :rtype: bytes
    """

    return hashlib.sha512(encode(data)).digest()


def sha512_256(data: Union[str, bytes]) -> bytes:
    """
    Calculate the SHA-512/256 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The SHA-512/256 hash digest as bytes.
    :rtype: bytes
    """

    if "sha512_256" in hashlib.algorithms_available:
        return hashlib.new("sha512_256", encode(data)).digest()
    return SHA512.new(encode(data), truncate="256").digest()


def sha3_256(data: Union[str, bytes]) -> bytes:
    """
    Calculate the SHA3-256 hash of the given data.

    :param data: The data to hash, as bytes or a string.
    :type data: Union[str, bytes]

    :return: The SHA3-256 hash digest as bytes.
    :rtype: bytes
    """

    if "sha3_256" in hashlib.algorithms_available:
        return hashlib.new("sha3_256", encode(data)).digest()
    return SHA3_256.new(encode(data)).digest()
