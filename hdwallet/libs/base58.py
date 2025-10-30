#!/usr/bin/env python3

from hashlib import sha256
from Crypto.Hash import keccak
from typing import List


__base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def checksum_encode(address, crypto="eth"):
    out = ""
    keccak_256 = keccak.new(digest_bits=256)
    addr = address.lower().replace("0x", "") if crypto == "eth" else address.lower().replace("xdc", "")
    keccak_256.update(addr.encode("ascii"))
    hash_addr = keccak_256.hexdigest()
    for i, c in enumerate(addr):
        if int(hash_addr[i], 16) >= 8:
            out += c.upper()
        else:
            out += c
    return ("0x" + out) if crypto == "eth" else ("xdc" + out)


def string_to_int(data):
    val = 0

    if isinstance(data, str):
        data = bytearray(data)

    for (i, c) in enumerate(data[::-1]):
        val += (256 ** i) * c
    return val


def ensure_string(data):
    if isinstance(data, bytes):
        return data.decode("utf-8")
    elif not isinstance(data, str):
        raise ValueError("Invalid value for string")
    return data


def encode(data, alphabet=__base58_alphabet):
    enc = ""
    val = string_to_int(data)
    while val >= len(alphabet):
        val, mod = divmod(val, len(alphabet))
        enc = alphabet[mod] + enc
    if val:
        enc = alphabet[val] + enc

    n = len(data) - len(data.lstrip(b"\0"))
    return alphabet[0] * n + enc


def check_encode(raw, alphabet=__base58_alphabet):
    chk = sha256(sha256(raw).digest()).digest()[:4]
    return encode(raw + chk, alphabet)


def decode(data, alphabet=__base58_alphabet):
    data = bytes(data, "ascii")

    val = 0
    prefix = 0
    for c in data:
        val = (val * len(alphabet)) + alphabet.encode("utf-8").find(c)
        if val == 0:
            prefix += 1

    dec = bytearray()
    while val > 0:
        val, mod = divmod(val, 256)
        dec.append(mod)

    dec.extend(bytearray(prefix))

    return bytes(dec[::-1])


def check_decode(enc, alphabet=__base58_alphabet):
    dec = decode(enc, alphabet)
    raw, chk = dec[:-4], dec[-4:]
    if chk != sha256(sha256(raw).digest()).digest()[:4]:
        raise ValueError("base58 decoding checksum error")
    else:
        return raw


def pad(enc: str, pad_len: int) -> str:
    return enc.rjust(pad_len, __base58_alphabet[0])


def encode_monero(data: bytes) -> str:
    enc = ""

    # Get lengths
    data_len: int = len(data)
    block_enc_len: int = 11
    block_dec_len: int = 8

    block_enc_bytes_lens: List[int] = [
        0, 2, 3, 5, 6, 7, 9, 10, 11
    ]

    # Compute total block count and last block length
    tot_block_cnt, last_block_enc_len = divmod(data_len, block_dec_len)

    # Encode each single block and pad
    for i in range(tot_block_cnt):
        block_enc = encode(data[i * block_dec_len:(i + 1) * block_dec_len])
        enc += pad(block_enc, block_enc_len)

    # Encode last block and pad
    if last_block_enc_len > 0:
        block_enc = encode(
            data[tot_block_cnt * block_dec_len:(tot_block_cnt * block_dec_len) + last_block_enc_len])
        enc += pad(block_enc, block_enc_bytes_lens[last_block_enc_len])

    return enc


def unpad(dec: bytes, unpad_len: int) -> bytes:
    return dec[len(dec) - unpad_len:len(dec)]


def decode_monero(data: str) -> bytes:
    dec = b""

    # Get lengths
    data_len: int = len(data)
    block_enc_len: int = 11
    block_dec_len: int = 8

    block_enc_bytes_lens: List[int] = [
        0, 2, 3, 5, 6, 7, 9, 10, 11
    ]

    # Compute block count and last block length
    tot_block_cnt, last_block_enc_len = divmod(data_len, block_enc_len)

    # Get last block decoded length
    last_block_dec_len = block_enc_bytes_lens.index(last_block_enc_len)

    # Decode each single block and unpad
    for i in range(tot_block_cnt):
        block_dec = decode(data[(i * block_enc_len):((i + 1) * block_enc_len)])
        dec += unpad(block_dec, block_dec_len)

    # Decode last block and unpad
    if last_block_enc_len > 0:
        block_dec = decode(
            data[(tot_block_cnt * block_enc_len):((tot_block_cnt * block_enc_len) + last_block_enc_len)])
        dec += unpad(block_dec, last_block_dec_len)

    return dec
