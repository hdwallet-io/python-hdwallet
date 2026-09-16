#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Tuple, Optional, Union
)

import struct

from .libs.base58 import (
    check_encode, check_decode
)
from .utils import (
    get_bytes, bytes_to_string, bytes_to_integer, integer_to_bytes
)
from .exceptions import ExtendedKeyError


def serialize(
    version: Union[str, bytes, int],
    depth: int,
    parent_fingerprint: Union[str, bytes],
    index: int,
    chain_code: Union[str, bytes],
    key: Union[str, bytes],
    encoded: bool = False
) -> Optional[str]:
    try:
        raw: bytes = (
            (integer_to_bytes(version) if isinstance(version, int) else get_bytes(version)) +
            bytes(bytearray([depth])) +
            get_bytes(parent_fingerprint) +
            struct.pack(">L", index) +
            get_bytes(chain_code) +
            get_bytes(key)
        )
        return check_encode(raw) if encoded else bytes_to_string(raw)
    except TypeError:
        return None


def deserialize(
    key: str, encoded: bool = True
) -> Tuple[bytes, int, bytes, int, bytes, bytes]:

    decoded_key: bytes = get_bytes(
        check_decode(key) if encoded else key
    )

    version, depth, parent_fingerprint, index, chain_code, key = (
        decoded_key[:4],
        bytes_to_integer(decoded_key[4:5]),
        decoded_key[5:9],
        struct.unpack(">L", decoded_key[9:13])[0],
        decoded_key[13:45],
        decoded_key[45:]
    )

    return (
        version, depth, parent_fingerprint, index, chain_code, key
    )


def is_valid_key(key: str, encoded: bool = True) -> bool:
    try:
        deserialize(key=key, encoded=encoded)
        return True
    except Exception:
        return False


def is_root_key(key: str, encoded: bool = True) -> bool:

    if not is_valid_key(key=key, encoded=encoded):
        raise ExtendedKeyError("Invalid extended(x) key")

    version, depth, parent_fingerprint, index, chain_code, key = deserialize(
        key=key, encoded=encoded
    )
    return (
        depth == 0 and
        parent_fingerprint == (integer_to_bytes(0x00) * 4) and
        index == 0
    )
