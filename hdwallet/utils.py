#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from random import choice
from typing import (
    List, Tuple, AnyStr, Optional, Union, Literal
)

import binascii
import string
import re

from .exceptions import DerivationError


def generate_passphrase(length: int = 32) -> str:
    """
    Generate a random passphrase.

    :param length: The length of the passphrase (default is 32).
    :type length: int

    :return: A randomly generated passphrase consisting of ASCII letters and digits.
    :rtype: str
    """

    return "".join(choice(string.ascii_letters + string.digits) for _ in range(length))


def get_hmac(ecc_name: str) -> bytes:
    """
    Return the HMAC seed for the specified elliptic curve algorithm.

    :param ecc_name: The name of the elliptic curve algorithm.
    :type ecc_name: str

    :return: The HMAC seed corresponding to the elliptic curve algorithm.
    :rtype: bytes
    """

    if ecc_name in [
        "Kholaw-Ed25519", "SLIP10-Ed25519", "SLIP10-Ed25519-Blake2b", "SLIP10-Ed25519-Monero"
    ]:
        return b"ed25519 seed"
    elif ecc_name == "SLIP10-Nist256p1":
        return b"Nist256p1 seed"
    elif ecc_name == "SLIP10-Secp256k1":
        return b"Bitcoin seed"


def exclude_keys(nested: dict, keys: set) -> dict:
    """
    Recursively exclude keys from a nested dictionary based on a set of keys.

    :param nested: The nested dictionary from which keys are to be excluded.
    :type nested: dict
    :param keys: A set of keys to exclude from the dictionary. Keys are checked after converting '-' to '_'.
    :type keys: set

    :return: A new dictionary with excluded keys.
    :rtype: dict
    """

    new: dict = { }
    for _key, _value in nested.items():
        if isinstance(_value, dict):
            new[_key] = exclude_keys(_value, keys)
        elif _key not in [key.replace("-", "_") if isinstance(key, str) else key for key in keys]:
            new[_key] = _value
    return new


def path_to_indexes(path: str) -> List[int]:
    """
    Convert a derivation path string into a list of indexes.

    :param path: The derivation path string, e.g., "m/0'/1/2'/2".
                 Should follow the format "m/0'/0" or similar.
    :type path: str

    :return: A list of indexes derived from the path, where hardened indexes
             have the highest bit set (0x80000000).
    :rtype: List[int]
        """

    if path in ["m", "m/"]:
        return []
    elif path[0:2] != "m/":
        raise DerivationError(
            "Bad path format", expected="like this type of path \"m/0'/0\"", got=path
        )

    indexes: List[int] = []
    for index in path.lstrip("m/").split("/"):
        indexes.append((int(index[:-1]) + 0x80000000) if "'" in index else int(index))
    return indexes


def indexes_to_path(indexes: List[int]) -> str:
    """
    Convert a list of indexes into a derivation path string.

    :param indexes: A list of indexes, where hardened indexes have the highest bit set (0x80000000).
    :type indexes: List[int]

    :return: The derivation path string generated from the list of indexes.
    :rtype: str
    """

    path: str = "m"
    for index in indexes:
        path += f"/{index - 0x80000000}'" if index & 0x80000000 else f"/{index}"
    return path


def normalize_index(
    index: Union[str, int, Tuple[int, int]], hardened: bool = False
) -> Union[Tuple[int, bool], Tuple[int, int, bool]]:
    """
    Normalize an index or range of indexes for derivation.

    :param index: The index or range of indexes to normalize.
                  Can be a single non-negative integer, a string representing a single index or range,
                  or a tuple of two integers representing a range.
                  For strings, the format should be "{non-negative-number}" or "{number}-{number}".
    :type index: Union[str, int, Tuple[int, int]]
    :param hardened: Whether the index is hardened (default is False).
    :type hardened: bool

    :return: A tuple representing the normalized index or range of indexes, optionally with hardened flag.
             For a single index: (index, hardened)
             For a range of indexes: (from_index, to_index, hardened)
    :rtype: Union[Tuple[int, bool], Tuple[int, int, bool]]
    """

    if isinstance(index, tuple):
        if len(index) != 2:
            raise DerivationError(
                "Bad index length", expected=2, got=len(index)
            )
        elif not isinstance(index[0], int) or not isinstance(index[1], int):
            raise DerivationError(
                "Invalid index types",
                expected="both indexes must be integer instance",
                got=f"{type(index[0])}-{type(index[0])}"
            )
        elif index[0] < 0 or index[1] < 0:
            raise DerivationError(
                "Bad index format", expected="both must be non-negative-numbers", got=index
            )
        elif index[0] > index[1]:
            raise DerivationError(
                f"Bad index, from {index[0]} index should be less than to {index[1]} index"
            )
        return *index, hardened

    elif isinstance(index, str):

        match: re.Match = re.match(
            r"^(\d+)(-(\d+))?$", index
        )
        if match:
            from_index: int = int(match.group(1))
            to_index: Optional[int] = (
                int(match.group(3)) if match.group(3) else None
            )
            if to_index is None:
                return from_index, hardened
            if from_index > to_index:
                raise DerivationError(
                    f"Bad index, from {from_index} index should be less than to {to_index} index"
                )
            return from_index, to_index, hardened
        raise DerivationError(
            "Bad index format", expected="{non-negative-number} | {number}-{number}", got=index
        )

    elif isinstance(index, int):
        if index < 0:
            raise DerivationError(
                "Bad index format", expected="non-negative-number", got=index
            )
        return index, hardened

    raise DerivationError(
        "Invalid index instance", expected=(str, int, tuple), got=type(index)
    )


def normalize_derivation(
    path: Optional[str] = None, indexes: Optional[List[int]] = None
) -> Tuple[str, List[int], List[tuple]]:
    """
    Normalize a derivation path string or indexes into a consistent format.

    :param path: The derivation path string to normalize, e.g., "m/0'/1/2'/2".
                 If provided, `indexes` should be None.
                 If path is None, a default path "m/" is returned.
    :type path: Optional[str]
    :param indexes: A list of indexes to convert into a derivation path string.
                    If provided, `path` should be None.
    :type indexes: Optional[List[int]]

    :return: A tuple containing the normalized derivation path string,
             list of indexes, and list of tuples representing derivation steps.
             The tuple structure:
             (normalized_path, normalized_indexes, derivations)
             where derivations is a list of tuples (index, hardened) or (from_index, to_index, hardened).
    :rtype: Tuple[str, List[int], List[tuple]]
    """

    _path: str = "m"
    _indexes: List[int] = []
    _derivations: List[tuple] = []

    if indexes:
        path = indexes_to_path(indexes=indexes)
    elif path:
        if path in ["m", "m/"]:
            return f"{_path}/", _indexes, _derivations
        elif path[0:2] != "m/":
            raise DerivationError(
                "Bad path format", expected="like this type of path \"m/0'/0\"", got=path
            )
    elif not path:
        return f"{_path}/", _indexes, _derivations

    for depth, index in enumerate(path.lstrip("m/").split("/")):
        if "'" in index:
            if "-" in index:
                _from_index, _to_index = index[:-1].split("-")
                _index: int = int(_to_index)
                if int(_from_index) >= int(_to_index):
                    raise DerivationError(
                        f"On {depth} depth, the starting {_from_index} must be less than the ending {_to_index} index"
                    )
                _derivations.append((int(_from_index), int(_to_index), True))
            else:
                _index: int = int(index[:-1])
                _derivations.append((_index, True))
            _indexes.append(_index + 0x80000000)
            _path += f"/{_index}'"
        else:
            if "-" in index:
                _from_index, _to_index = index.split("-")
                _index: int = int(_to_index)
                if int(_from_index) >= int(_to_index):
                    raise DerivationError(
                        f"On {depth} depth, the starting {_from_index} must be less than the ending {_to_index} index"
                    )
                _derivations.append((int(_from_index), int(_to_index), False))
            else:
                _index: int = int(index)
                _derivations.append((_index, False))
            _indexes.append(_index)
            _path += f"/{_index}"

    return _path, _indexes, _derivations


def index_tuple_to_integer(index: Union[Tuple[int, bool], Tuple[int, int, bool]]) -> int:
    """
    Convert a tuple representing an index or range of indexes into a single integer.

    :param index: The tuple representing an index or range of indexes.
                  For a single index: (index, hardened)
                  For a range of indexes: (from_index, to_index, hardened)
    :type index: Union[Tuple[int, bool], Tuple[int, int, bool]]

    :return: The integer representation of the index, with hardening flag applied if present.
    :rtype: int
    """

    if not isinstance(index, tuple):
        raise DerivationError("Invalid index instance", expected=tuple, got=type(index))
    elif len(index) == 3:
        return (index[1] + 0x80000000) if index[2] else index[0]
    elif len(index) == 2:
        return (index[0] + 0x80000000) if index[1] else index[0]
    raise DerivationError("Wrong index length", expected=[2, 3], got=len(index))


def index_tuple_to_string(index: Union[Tuple[int, bool], Tuple[int, int, bool]]) -> str:
    """
    Convert a tuple representing an index or range of indexes into a string representation.

    :param index: The tuple representing an index or range of indexes.
                  For a single index: (index, hardened)
                  For a range of indexes: (from_index, to_index, hardened)
    :type index: Union[Tuple[int, bool], Tuple[int, int, bool]]

    :return: The string representation of the index or range of indexes.
    :rtype: str
    """

    if not isinstance(index, tuple):
        raise DerivationError("Invalid index instance", expected=tuple, got=type(index))
    elif len(index) == 3:
        _from_index, _to_index, _hardened = index[0], index[1], "'" if index[2] else ""
        return f"{_from_index}-{_to_index}{_hardened}"
    elif len(index) == 2:
        _index, _hardened = index[0], "'" if index[1] else ""
        return f"{_index}{_hardened}"
    raise DerivationError("Wrong index length", expected=[2, 3], got=len(index))


def index_string_to_tuple(index: str) -> Tuple[int, bool]:
    """
    Convert a string representation of an index into a tuple.

    :param index: The string representation of the index, which may include a trailing apostrophe (').
    :type index: str

    :return: A tuple representing the index and whether it is hardened (True) or not (False).
    :rtype: Tuple[int, bool]
    """

    index_split: List[str] = index.split("'")
    return (
        (int(index_split[0]), True)
        if index.endswith("'") else
        (int(index_split[0]), False)
    )


def xor(data_1: bytes, data_2: bytes) -> bytes:
    """
    Perform bitwise XOR operation between two bytes objects.

    :param data_1: The first bytes object for XOR operation.
    :type data_1: bytes
    :param data_2: The second bytes object for XOR operation. It must be of the same length as data_1.
    :type data_2: bytes

    :return: The result of XOR operation as a bytes object.
    :rtype: bytes
    """

    return bytes(
        [b1 ^ b2 for b1, b2 in zip(data_1, data_2)]
    )


def add_no_carry(data_1: bytes, data_2: bytes) -> bytes:
    """
    Perform addition without carry between two bytes objects.

    :param data_1: The first bytes object for addition without carry.
    :type data_1: bytes
    :param data_2: The second bytes object for addition without carry. It must be of the same length as data_1.
    :type data_2: bytes

    :return: The result of addition without carry as a bytes object.
    :rtype: bytes
    """

    return bytes(
        [(b1 + b2) & 0xFF for b1, b2 in zip(data_1, data_2)]
    )


def multiply_scalar_no_carry(data: bytes, scalar: int) -> bytes:
    """
    Multiply each byte in a bytes object by a scalar without carry.

    :param data: The bytes object to multiply.
    :type data: bytes
    :param scalar: The scalar value to multiply each byte by.
    :type scalar: int

    :return: The result of multiplying each byte by the scalar, without carry, as a bytes object.
    :rtype: bytes
    """

    return bytes(
        [(b * scalar) & 0xFF for b in data]
    )


def is_bits_set(value: int, bit_num: int) -> bool:
    """
    Check if a specific bit in an integer value is set (i.e., equals 1).

    :param value: The integer value to check.
    :type value: int
    :param bit_num: The bit number to check (0-indexed, from the right).
    :type bit_num: int

    :return: True if the specified bit in `value` is set (equals 1), False otherwise.
    :rtype: bool
    """

    return (value & (1 << bit_num)) != 0


def are_bits_set(value: int, bit_mask: int) -> bool:
    """
    Check if specific bits in an integer value are set according to a bitmask.

    :param value: The integer value to check.
    :type value: int
    :param bit_mask: The bitmask representing which bits to check. Bits set to 1 in the bitmask will be checked in `value`.
    :type bit_mask: int

    :return: True if any of the bits set in `bit_mask` are also set in `value`, False otherwise.
    :rtype: bool
    """

    return (value & bit_mask) != 0


def set_bit(value: int, bit_num: int) -> int:
    """
    Set a specific bit in an integer value to 1.

    :param value: The integer value in which to set the bit.
    :type value: int
    :param bit_num: The bit number to set (0-indexed, from the right).
    :type bit_num: int

    :return: The integer value with the specified bit set to 1.
    :rtype: int
    """

    return value | (1 << bit_num)


def set_bits(value: int, bit_mask: int) -> int:
    """
    Set specific bits in an integer value according to a bitmask.

    :param value: The integer value in which to set the bits.
    :type value: int
    :param bit_mask: The bitmask representing which bits to set. Bits set to 1 in the bitmask will be set in `value`.
    :type bit_mask: int

    :return: The integer value with the specified bits set according to the bitmask.
    :rtype: int
    """

    return value | bit_mask


def reset_bit(value: int, bit_num: int) -> int:
    """
    Reset (clear) a specific bit in an integer value to 0.

    :param value: The integer value in which to reset the bit.
    :type value: int
    :param bit_num: The bit number to reset (0-indexed, from the right).
    :type bit_num: int

    :return: The integer value with the specified bit reset to 0.
    :rtype: int
    """

    return value & ~(1 << bit_num)


def reset_bits(value: int, bit_mask: int) -> int:
    """
    Reset (clear) specific bits in an integer value according to a bitmask.

    :param value: The integer value in which to reset the bits.
    :type value: int
    :param bit_mask: The bitmask representing which bits to reset. Bits set to 1 in the bitmask will be cleared in `value`.
    :type bit_mask: int

    :return: The integer value with the specified bits reset according to the bitmask.
    :rtype: int
    """

    return value & ~bit_mask


def get_bytes(data: AnyStr, unhexlify: bool = True) -> bytes:
    """
    Convert input data to bytes format.

    :param data: The input data to convert. Can be bytes or string.
    :type data: Union[bytes, str]
    :param unhexlify: Flag indicating whether to interpret strings as hexadecimal (default True).
    :type unhexlify: bool

    :return: The input data converted to bytes format.
    :rtype: bytes
    """

    if not data:
        return b''
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        if unhexlify:
            return bytes.fromhex(data)
        else:
            return bytes(data, 'utf-8')
    else:
        raise TypeError("Agreement must be either 'bytes' or 'str'!")


def bytes_reverse(data: bytes) -> bytes:
    """
    Reverse the order of bytes in a bytes object.

    :param data: The bytes object to reverse.
    :type data: bytes

    :return: The bytes object with its byte order reversed.
    :rtype: bytes
    """

    tmp = bytearray(data)
    tmp.reverse()
    return bytes(tmp)


def bytes_to_string(data: AnyStr, unhexlify: Optional[bool] = None) -> str:
    """Convert bytes or string (hexadecimal, or UTF-8 decoded) data to a hexadecimal string representation.

    If the default unhexlify == None is provided, will attempt to auto-detect non-empty hex strings,
    and thus reject hex strings of accidentally odd length instead of accepting them (surprisingly
    and almost certainly incorrectly!) as UTF-8 encoded binary data (get_bytes is resilient to
    surrounding whitespace, so we must be, too).

    :param data: The bytes or string data to convert to hexadecimal string.
    :type data: Union[bytes, str]
    :param unhexlify: Flag indicating whether to interpret strings as hexadecimal (default None).
    :type unhexlify: Optional[bool]

    :return: The hexadecimal string representation of the input data, empty if no data.
    :rtype: str

    """

    if not data:
        return ''
    if unhexlify is None:
        unhexlify = isinstance(data, str) and all(c in string.hexdigits for c in data.strip())
    binary = get_bytes(data, unhexlify=unhexlify)
    return binary.hex()


def bytes_to_integer(data: bytes, endianness: Literal["little", "big"] = "big", signed: bool = False) -> int:
    """
    Convert bytes to an integer based on specified endianness and signedness.

    :param data: The bytes object to convert to an integer.
    :type data: bytes
    :param endianness: The byte order ("little" or "big").
    :type endianness: Literal["little", "big"]
    :param signed: Flag indicating whether the integer is signed (default False).
    :type signed: bool

    :return: The integer value converted from bytes.
    :rtype: int
    """

    return int.from_bytes(data, byteorder=endianness, signed=signed)


def integer_to_bytes(data: int, bytes_num: Optional[int] = None, endianness: Literal["little", "big"] = "big", signed: bool = False) -> bytes:
    """
    Convert an integer to bytes based on specified parameters.

    :param data: The integer to convert to bytes.
    :type data: int
    :param bytes_num: Optional number of bytes to use for the conversion. If not provided, it is calculated based on the integer's bit length.
    :type bytes_num: Optional[int]
    :param endianness: The byte order ("little" or "big").
    :type endianness: Literal["little", "big"]
    :param signed: Flag indicating whether the integer is signed (default False).
    :type signed: bool

    :return: The bytes object representing the integer.
    :rtype: bytes
    """

    bytes_num = bytes_num or ((data.bit_length() if data > 0 else 1) + 7) // 8
    return data.to_bytes(bytes_num, byteorder=endianness, signed=signed)


def integer_to_binary_string(data: int, zero_pad_bit_len: int = 0) -> str:
    """
    Convert an integer to a binary string representation.

    :param data: The integer to convert to binary string.
    :type data: int
    :param zero_pad_bit_len: Optional number of bits to zero-pad the binary string (default 0).
    :type zero_pad_bit_len: int

    :return: The binary string representation of the integer.
    :rtype: str
    """

    return bin(data)[2:].zfill(zero_pad_bit_len)


def binary_string_to_integer(data: Union[bytes, str]) -> int:
    """
    Convert a binary string representation to an integer.

    :param data: The binary string or bytes object to convert to an integer.
    :type data: Union[bytes, str]

    :return: The integer value converted from the binary representation.
    :rtype: int
    """

    return int((data.encode("utf-8") if isinstance(data, str) else data), 2)


def bytes_to_binary_string(data: bytes, zero_pad_bit_len: int = 0) -> str:
    """
    Convert bytes to a binary string representation.

    :param data: The bytes object to convert to binary string.
    :type data: bytes
    :param zero_pad_bit_len: Optional number of bits to zero-pad the binary string (default 0).
    :type zero_pad_bit_len: int

    :return: The binary string representation of the bytes.
    :rtype: str
    """

    return integer_to_binary_string(bytes_to_integer(data), zero_pad_bit_len)


def binary_string_to_bytes(data: Union[bytes, str], zero_pad_byte_len: int = 0) -> bytes:
    """
    Convert a binary string representation to bytes.

    :param data: The binary string or bytes object to convert to bytes.
    :type data: Union[bytes, str]
    :param zero_pad_byte_len: Optional number of bytes to zero-pad the resulting bytes object (default 0).
    :type zero_pad_byte_len: int

    :return: The bytes object converted from the binary representation.
    :rtype: bytes
    """

    return binascii.unhexlify(hex(binary_string_to_integer(data))[2:].zfill(zero_pad_byte_len))


def decode(data: Union[bytes, str], encoding: str = "utf-8") -> str:
    """
    Decode bytes or return a string unchanged.

    :param data: The bytes or string data to decode.
    :type data: Union[bytes, str]
    :param encoding: The encoding to use when decoding bytes (default is 'utf-8').
    :type encoding: str

    :return: The decoded string if data is bytes; otherwise, returns the input string unchanged.
    :rtype: str
    """

    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode(encoding)
    raise TypeError("Invalid data type")


def encode(data: Union[bytes, str], encoding: str = "utf-8") -> bytes:
    """
    Encode string or return bytes unchanged.

    :param data: The string or bytes data to encode.
    :type data: Union[bytes, str]
    :param encoding: The encoding to use when encoding a string to bytes (default is 'utf-8').
    :type encoding: str

    :return: The encoded bytes if data is string; otherwise, returns the input bytes unchanged.
    :rtype: bytes
    """

    if isinstance(data, str):
        return data.encode(encoding)
    if isinstance(data, bytes):
        return data
    raise TypeError("Invalid data type")


def convert_bits(
    data: Union[bytes, List[int]], from_bits: int, to_bits: int
) -> Optional[List[int]]:
    """
    Convert data represented by 'from_bits' into 'to_bits' per element.

    :param data: The data to convert, represented as bytes or a list of integers.
    :type data: Union[bytes, List[int]]
    :param from_bits: Number of bits each element of 'data' represents initially.
    :type from_bits: int
    :param to_bits: Number of bits each element of the result should represent after conversion.
    :type to_bits: int

    :return: The converted data as a list of integers, or None if conversion fails.
    :rtype: Optional[List[int]]
    """

    max_out_val = (1 << to_bits) - 1

    acc = 0
    bits = 0
    ret = []

    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc |= value << bits
        bits += from_bits
        while bits >= to_bits:
            ret.append(acc & max_out_val)
            acc = acc >> to_bits
            bits -= to_bits

    if bits != 0:
        ret.append(acc & max_out_val)

    return ret


def bytes_chunk_to_words(
    bytes_chunk: bytes, words_list: List[str], endianness: Literal["little", "big"]
) -> List[str]:
    """
    Convert a bytes chunk into a list of words based on a given word list and endianness.

    :param bytes_chunk: The bytes chunk to convert into words.
    :type bytes_chunk: bytes
    :param words_list: The list of words to choose from when converting.
    :type words_list: List[str]
    :param endianness: The endianness to use when interpreting the bytes chunk ("little" or "big").
    :type endianness: Literal["little", "big"]

    :return: A list of three words selected from words_list based on the bytes chunk.
    :rtype: List[str]
    """

    words_list_length = len(words_list)

    chunk: int = bytes_to_integer(bytes_chunk, endianness=endianness)

    word_1_index = chunk % words_list_length
    word_2_index = ((chunk // words_list_length) + word_1_index) % words_list_length
    word_3_index = ((chunk // words_list_length // words_list_length) + word_2_index) % words_list_length

    return [words_list[index] for index in (word_1_index, word_2_index, word_3_index)]


def words_to_bytes_chunk(
    word_1: str, word_2: str, word_3: str, words_list: List[str], endianness: Literal["little", "big"]
) -> bytes:
    """
    Convert three words into a bytes chunk based on a given word list and endianness.

    :param word_1: The first word to convert.
    :type word_1: str
    :param word_2: The second word to convert.
    :type word_2: str
    :param word_3: The third word to convert.
    :type word_3: str
    :param words_list: The list of words from which to select the words.
    :type words_list: List[str]
    :param endianness: The endianness to use when encoding the chunk into bytes ("little" or "big").
    :type endianness: Literal["little", "big"]

    :return: The bytes chunk representing the three words.
    :rtype: bytes
    """

    words_list_length = len(words_list)
    words_list_with_index: dict = {
        words_list[i]: i for i in range(len(words_list))
    }

    word_1_index, word_2_index, word_3_index = (
        words_list_with_index[word_1], words_list_with_index[word_2] % words_list_length, words_list_with_index[word_3] % words_list_length
    )

    chunk: int = (
        word_1_index + (
            words_list_length * ((word_2_index - word_1_index) % words_list_length)
        ) + (
            words_list_length * words_list_length * ((word_3_index - word_2_index) % words_list_length)
        )
    )

    return integer_to_bytes(
        chunk, bytes_num=4, endianness=endianness
    )
