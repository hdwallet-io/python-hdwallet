#!/usr/bin/env python3

# Copyright © 2023-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Tuple
)

from .libs.base58 import (
    encode, decode
)
from .cryptocurrencies import Bitcoin
from .consts import (
    SLIP10_SECP256K1_CONST, WIF_TYPES
)
from .crypto import get_checksum
from .exceptions import (
    WIFError, ECCError
)
from .utils import (
    get_bytes, integer_to_bytes, bytes_to_string
)


def encode_wif(
    private_key: Union[str, bytes], wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> Tuple[str, str]:
    """
    Encode a private key to Wallet Import Format (WIF).

    :param private_key: The private key to encode, as a 32-byte string or bytes.
    :type private_key: Union[str, bytes]
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: A tuple containing the WIF and WIF-compressed formats.
    :rtype: Tuple[str, str]
    """

    if len(get_bytes(private_key)) != 32:
        raise ECCError("Invalid private key length", expected=64, got=len(private_key))

    wif_payload: bytes = (
        integer_to_bytes(wif_prefix) + get_bytes(private_key)
    )
    wif_compressed_payload: bytes = (
        integer_to_bytes(wif_prefix) + get_bytes(private_key) + integer_to_bytes(SLIP10_SECP256K1_CONST.PRIVATE_KEY_COMPRESSED_PREFIX)
    )
    return (
        encode(wif_payload + get_checksum(wif_payload)),
        encode(wif_compressed_payload + get_checksum(wif_compressed_payload))
    )


def decode_wif(
    wif: str, wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> Tuple[bytes, str, bytes]:
    """
    Decode a Wallet Import Format (WIF) string to a private key.

    :param wif: The WIF string to decode.
    :type wif: str
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: A tuple containing the private key, the WIF type, and the checksum.
    :rtype: Tuple[bytes, str, bytes]
    """

    raw: bytes = decode(wif)
    if not raw.startswith(integer_to_bytes(wif_prefix)):
        raise WIFError("Invalid Wallet Import Format (WIF)")

    prefix_length: int = len(integer_to_bytes(wif_prefix))
    prefix_got: bytes = raw[:prefix_length]
    if integer_to_bytes(wif_prefix) != prefix_got:
        raise WIFError("Invalid WIF prefix", expected=prefix_length, got=prefix_got)

    raw_without_prefix: bytes = raw[prefix_length:]
    checksum: bytes = raw_without_prefix[-1 * 4:]
    private_key: bytes = raw_without_prefix[:-1 * 4]
    wif_type: str = "wif"

    if len(private_key) not in [33, 32]:
        raise WIFError("Invalid Wallet Import Format (WIF)")
    elif len(private_key) == 33:
        private_key = private_key[:-len(integer_to_bytes(SLIP10_SECP256K1_CONST.PRIVATE_KEY_COMPRESSED_PREFIX))]
        wif_type = "wif-compressed"

    return private_key, wif_type, checksum


def private_key_to_wif(
    private_key: Union[str, bytes],
    wif_type: str = "wif-compressed",
    wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> str:
    """
    Convert a private key to Wallet Import Format (WIF).

    :param private_key: The private key to convert, as a 32-byte string or bytes.
    :type private_key: Union[str, bytes]
    :param wif_type: The WIF type, Default to ``wif-compressed``.
    :type wif_type: str
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: The private key in WIF format.
    :rtype: str
    """

    if wif_type not in WIF_TYPES.get_types():
        raise WIFError("Wrong WIF type", expected=WIF_TYPES.get_types(), got=wif_type)
    wif, wif_compressed = encode_wif(
        private_key=private_key, wif_prefix=wif_prefix
    )
    return wif if wif_type == "wif" else wif_compressed


def wif_to_private_key(
    wif: str, wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> str:
    """
    Convert a Wallet Import Format (WIF) string to a private key.

    :param wif: The WIF string to decode.
    :type wif: str
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: The private key as a string.
    :rtype: str
    """

    return bytes_to_string(decode_wif(
        wif=wif, wif_prefix=wif_prefix
    )[0])


def get_wif_type(
    wif: str, wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> str:
    """
    Get the type of Wallet Import Format (WIF) string.

    :param wif: The WIF string to inspect.
    :type wif: str
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: The WIF type ('wif' or 'wif-compressed').
    :rtype: str
    """

    return decode_wif(
        wif=wif, wif_prefix=wif_prefix
    )[1]


def get_wif_checksum(
    wif: str, wif_prefix: int = Bitcoin.NETWORKS.MAINNET.WIF_PREFIX
) -> str:
    """
    Get the checksum of a Wallet Import Format (WIF) string.

    :param wif: The WIF string to inspect.
    :type wif: str
    :param wif_prefix: The prefix to use for the WIF, Defaults to Bitcoin mainnet prefix.
    :type wif_prefix: int

    :returns: The checksum as a string.
    :rtype: str
    """

    return bytes_to_string(decode_wif(
        wif=wif, wif_prefix=wif_prefix
    )[2])
