#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import pytest
from hdwallet.crypto import (
    hmac_sha256, hmac_sha512, blake2b, blake2b_32, blake2b_40, blake2b_160, blake2b_224, blake2b_256, blake2b_512,
    chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, sha256, double_sha256, hash160, crc32, xmodem_crc, 
    pbkdf2_hmac_sha512, keccak256, ripemd160, sha512, sha512_256, sha3_256
)

# def test_hmac_sha256():
#     assert hmac_sha256("key", "data") == b'todo_mock'
#     assert hmac_sha256(b"key", b"data") == b'todo_mock'

# def test_hmac_sha512():
#     assert hmac_sha512("key", "data") == b'todo_mock'
#     assert hmac_sha512(b"key", b"data") == b'todo_mock'

# def test_blake2b():
#     assert blake2b("data", 64) == b'todo_mock'

# def test_blake2b_32():
#     assert blake2b_32("data") == b'todo_mock'

# def test_blake2b_40():
#     assert blake2b_40("data") == b'todo_mock'

# def test_blake2b_160():
#     assert blake2b_160("data") == b'todo_mock'

# def test_blake2b_224():
#     assert blake2b_224("data") == b'todo_mock'

# def test_blake2b_256():
#     assert blake2b_256("data") == b'todo_mock'

# def test_blake2b_512():
#     assert blake2b_512("data") == b'todo_mock'

# def test_chacha20_poly1305_encrypt_decrypt():
#     key = b'0' * 32
#     nonce = b'0' * 12
#     assoc_data = b'header'
#     plain_text = b'plaintext'
#     cipher_text, tag = chacha20_poly1305_encrypt(key, nonce, assoc_data, plain_text)
#     decrypted_text = chacha20_poly1305_decrypt(key, nonce, assoc_data, cipher_text, tag)
#     assert decrypted_text == plain_text

# def test_sha256():
#     assert sha256("data") == b'todo_mock'

# def test_double_sha256():
#     assert double_sha256("data") == b'todo_mock'

# def test_hash160():
#     assert hash160("data") == b'todo_mock'

# def test_crc32():
#     assert crc32("data") == b'todo_mock'

# def test_xmodem_crc():
#     assert xmodem_crc("data") == b'todo_mock'

# def test_pbkdf2_hmac_sha512():
#     assert pbkdf2_hmac_sha512("password", "salt", 1000) == b'todo_mock'

# def test_keccak256():
#     assert keccak256("data") == b'todo_mock'

# def test_ripemd160():
#     assert ripemd160("data") == b'todo_mock'

# def test_sha512():
#     assert sha512("data") == b'todo_mock'

# def test_sha512_256():
#     assert sha512_256("data") == b'todo_mock'

# def test_sha3_256():
#     assert sha3_256("data") == b'todo_mock'
