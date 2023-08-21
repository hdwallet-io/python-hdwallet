#!/usr/bin/env python3

"""
The MIT License (MIT)

Copyright © 2021-2022 by Meheret Tesfaye Batu <meherett.batu@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.keys import (
    SigningKey, VerifyingKey
)
from ecdsa.util import sigencode_der
from ecdsa.ecdsa import (
    int_to_string, string_to_int
)
from binascii import (
    hexlify, unhexlify
)
from typing import (
    Tuple, Union, Optional
)
from mnemonic import Mnemonic
from hashlib import sha256
from typing import (
    Optional, Any, Union
)
from functools import partial

import hmac
import ecdsa
import struct
from Crypto.Hash import keccak
import unicodedata
import hashlib
import base58

from .libs.ripemd160 import ripemd160
from .libs.ecc import S256Point, N, G
from .libs.bech32 import (
    bech32_encode, encode, bech32_decode, decode
)
from .libs.base58 import (
    check_encode, checksum_encode, check_decode, ensure_string
)
from .cryptocurrencies import (
    Cryptocurrency, get_cryptocurrency, SegwitAddress
)
from .derivations import (
    Derivation, BIP32Derivation, BIP44Derivation, BIP49Derivation, BIP84Derivation, BIP141Derivation
)
from .exceptions import (
    SemanticError, DerivationError
)
from .utils import (
    get_bytes, is_entropy, is_mnemonic, get_entropy_strength, _unhexlify, is_root_xpublic_key,
    get_mnemonic_language, is_root_xprivate_key, get_mnemonic_strength, get_semantic
)

MIN_ENTROPY_LEN: int = 128
BIP32KEY_HARDEN: int = 0x80000000
highest_s = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0

CURVE_GEN: Any = ecdsa.ecdsa.generator_secp256k1
CURVE_ORDER: int = CURVE_GEN.order()
FIELD_ORDER: int = SECP256k1.curve.p()
INFINITY: Point = ecdsa.ellipticcurve.INFINITY


class HDWallet:
    """
    Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, defaults to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param semantic: Extended semantic, defaults to ``P2PKH``.
    :type semantic: str
    :param use_default_path: Use default derivation path, defaults to ``False``.
    :type use_default_path: bool

    :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

    .. note::
        To initialize HDWallet symbol or cryptocurrency is required.
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 semantic: Optional[str] = None, use_default_path: bool = False):
        self._cryptocurrency: Any = None
        if cryptocurrency:
            if not issubclass(cryptocurrency, Cryptocurrency):
                raise TypeError("Invalid Cryptocurrency type, the sub class must be Cryptocurrency instance.")
            self._cryptocurrency: Any = cryptocurrency
        else:
            self._cryptocurrency: Any = get_cryptocurrency(symbol=symbol)

        self._strength: Optional[int] = None
        self._entropy: Optional[str] = None
        self._mnemonic: Optional[str] = None
        self._language: Optional[str] = None
        self._passphrase: Optional[str] = None

        self._use_default_path: bool = use_default_path
        self._parent_fingerprint: bytes = b"\0\0\0\0"
        self._i: Optional[bytes] = None
        self._path: str = "m"

        self._seed: Optional[bytes] = None
        self._private_key: Optional[bytes] = None
        self._key: Optional[SigningKey] = None
        self._verified_key: Optional[VerifyingKey] = None
        self._semantic: str = semantic
        self._from_class: bool = False
        self._path_class: str = "m"

        self._root_private_key: Optional[tuple] = None
        self._root_public_key: Optional[tuple] = None
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[str] = None
        self._chain_code: Optional[bytes] = None
        self._depth: int = 0
        self._index: int = 0

        self._root_depth: int = 0
        self._root_parent_fingerprint: bytes = b"\0\0\0\0"
        self._root_index: int = 0

    def from_entropy(self, entropy: str, language: str = "english", passphrase: str = None) -> "HDWallet":
        """
        Master from Entropy hex string.

        :param entropy: Entropy hex string.
        :type entropy: str
        :param language: Mnemonic language, default to ``english``.
        :type language: str
        :param passphrase: Mnemonic passphrase or password, default to ``None``.
        :type passphrase: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a", language="english", passphrase=None)
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if not is_entropy(entropy=entropy):
            raise ValueError("Invalid entropy.")
        if language and language not in ["english", "french", "italian", "japanese",
                                         "chinese_simplified", "chinese_traditional", "korean", "spanish"]:
            raise ValueError("Invalid language, choose only the following options 'english', 'french', 'italian', "
                             "'spanish', 'chinese_simplified', 'chinese_traditional', 'japanese' or 'korean' languages.")

        self._strength = get_entropy_strength(entropy=entropy)
        self._entropy, self._language = unhexlify(entropy), language
        self._passphrase = str(passphrase) if passphrase else str()
        mnemonic = Mnemonic(language=self._language).to_mnemonic(data=self._entropy)
        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_mnemonic(self, mnemonic: str, language: str = None, passphrase: str = None) -> "HDWallet":
        """
        Master from Mnemonic words.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param language: Mnemonic language, default to ``None``.
        :type language: str
        :param passphrase: Mnemonic passphrase or password, default to ``None``.
        :type passphrase: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="sceptre capter séquence girafe absolu relatif fleur zoologie muscle sirop saboter parure", passphrase=None)
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if not is_mnemonic(mnemonic=mnemonic, language=language):
            raise ValueError("Invalid mnemonic words.")

        self._mnemonic = unicodedata.normalize("NFKD", mnemonic)
        self._strength = get_mnemonic_strength(mnemonic=self._mnemonic)
        self._language = language if language else get_mnemonic_language(mnemonic=self._mnemonic)
        self._entropy = Mnemonic(language=self._language).to_entropy(self._mnemonic)
        self._passphrase = str(passphrase) if passphrase else str()
        self._seed = Mnemonic.to_seed(mnemonic=self._mnemonic, passphrase=self._passphrase)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self.from_seed(seed=hexlify(self._seed).decode())

    def from_seed(self, seed: str) -> "HDWallet":
        """
        Master from Seed hex string.

        :param seed: Seed hex string.
        :type seed: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import ETH
        >>> hdwallet = HDWallet(symbol=ETH)
        >>> hdwallet.from_seed(seed="8d5f4fe5b81a6a6a18b08603b6b3f59df9f4bbb25d10c55d23e0cbdc5ee385e5fddad9d7e6114f11afdec45928328081f9a598151a7613dc5f5a0c16a4612aa4")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        self._seed = unhexlify(seed)
        self._i = hmac.new(b"Bitcoin seed", get_bytes(seed), hashlib.sha512).digest()
        il, ir = self._i[:32], self._i[32:]
        self._root_private_key = (il, ir)
        parse_il = int.from_bytes(il, "big")
        if parse_il == 0 or parse_il >= SECP256k1.order:
            raise ValueError("Bad seed, resulting in invalid key!")

        self._private_key, self._chain_code = il, ir
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        self._public_key = self.compressed()
        if self._from_class:
            self.from_path(path=self._path_class)
        if self._semantic is None:
            self._semantic = "p2pkh"
        return self

    def from_xprivate_key(self, xprivate_key: str, strict: bool = False) -> "HDWallet":
        """
        Master from XPrivate Key.

        :param xprivate_key: Root or Non-Root XPrivate key.
        :type xprivate_key: str
        :param strict: Strict for must be root xprivate key, default to ``False``.
        :type strict: bool

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_xprivate_key(xprivate_key="xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if not is_root_xprivate_key(xprivate_key=xprivate_key, symbol=self._cryptocurrency.SYMBOL):
            if strict:
                raise ValueError("Invalid root xprivate key.")

        _deserialize_xprivate_key = self._deserialize_xprivate_key(xprivate_key=xprivate_key)
        self._root_depth, self._root_parent_fingerprint, self._root_index = (
            int.from_bytes(_deserialize_xprivate_key[1], "big"),
            _deserialize_xprivate_key[2],
            struct.unpack(">L", _deserialize_xprivate_key[3])[0]
        )
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_deserialize_xprivate_key[1], "big"),
            _deserialize_xprivate_key[2],
            struct.unpack(">L", _deserialize_xprivate_key[3])[0]
        )
        self._i = _deserialize_xprivate_key[5] + _deserialize_xprivate_key[4]
        self._root_private_key = (_deserialize_xprivate_key[5], _deserialize_xprivate_key[4])
        self._private_key, self._chain_code = self._i[:32], self._i[32:]
        self._key = ecdsa.SigningKey.from_string(_deserialize_xprivate_key[5], curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        if self._from_class:
            self.from_path(path=self._path_class)
        self._public_key = self.compressed()
        self._semantic = get_semantic(
            _cryptocurrency=self._cryptocurrency,
            version=_deserialize_xprivate_key[0],
            key_type="private_key"
        )
        return self

    def from_xpublic_key(self, xpublic_key: str, strict: bool = False) -> "HDWallet":
        """
        Master from XPublic Key.

        :param xpublic_key: Root or Non-Root XPublic key.
        :type xpublic_key: str
        :param strict: Strict for must be root xpublic key, default to ``False``.
        :type strict: bool

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_xpublic_key(xpublic_key="xpub661MyMwAqRbcGSTjb2Mp3Sb4STUDhD2x986ubXKjQa2QsFTCVqzdA98qeZjcncHT1AaZcMSjiP1HJ16jH97q72RwyFfiNhmG8zQ6KBB5PaQ")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if not is_root_xpublic_key(xpublic_key=xpublic_key, symbol=self._cryptocurrency.SYMBOL):
            if strict:
                raise ValueError("Invalid root xpublic key.")

        _deserialize_xpublic_key = self._deserialize_xpublic_key(xpublic_key=xpublic_key)
        self._root_depth, self._root_parent_fingerprint, self._root_index = (
            int.from_bytes(_deserialize_xpublic_key[1], "big"),
            _deserialize_xpublic_key[2],
            struct.unpack(">L", _deserialize_xpublic_key[3])[0]
        )
        self._depth, self._parent_fingerprint, self._index = (
            int.from_bytes(_deserialize_xpublic_key[1], "big"),
            _deserialize_xpublic_key[2],
            struct.unpack(">L", _deserialize_xpublic_key[3])[0]
        )
        self._chain_code = _deserialize_xpublic_key[4]
        self._verified_key = ecdsa.VerifyingKey.from_string(
            _deserialize_xpublic_key[5], curve=SECP256k1
        )
        self._root_public_key = (
            _deserialize_xpublic_key[5], _deserialize_xpublic_key[4]
        )
        if self._use_default_path:
            self.from_path(path=self._cryptocurrency.DEFAULT_PATH)
        if self._from_class:
            self.from_path(path=str(self._path_class).replace("'", ""))
        self._public_key = self.compressed()
        self._semantic = get_semantic(
            _cryptocurrency=self._cryptocurrency,
            version=_deserialize_xpublic_key[0],
            key_type="public_key"
        )
        return self

    def from_wif(self, wif: str) -> "HDWallet":
        """
        Master from Wallet Important Format (WIF).

        :param wif: Wallet important format.
        :type wif: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_wif(wif="KzsHWUJsrTWUUhBGPfMMxLLydiH7NhEn6z7mKHXD5qNkUWaC4TEn")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        raw = check_decode(wif)[:-1]
        if not raw.startswith(_unhexlify(self._cryptocurrency.WIF_SECRET_KEY)):
            raise ValueError(f"Invalid {self.cryptocurrency()} wallet important format.")

        self._private_key = raw.split(_unhexlify(self._cryptocurrency.WIF_SECRET_KEY), 1).pop()
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_private_key(self, private_key: str) -> "HDWallet":
        """
        Master from Private Key.

        :param private_key: Private key.
        :type private_key: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_private_key(private_key="6cd78b0d69eab1a47bfa53a52b9d8c4331e858b5d7a599270a95d9735fdb0b94")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        self._private_key = unhexlify(private_key)
        self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
        self._verified_key = self._key.get_verifying_key()
        self._public_key = self.compressed()
        return self

    def from_public_key(self, public_key: str) -> "HDWallet":
        """
        Master from Public Key.

        :param public_key: Public key.
        :type public_key: str

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_public_key(public_key="02f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a8")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        self._verified_key = ecdsa.VerifyingKey.from_string(
            unhexlify(public_key), curve=SECP256k1
        )
        self._public_key = self.compressed()
        return self

    def from_path(self, path: Union[str, Derivation]) -> "HDWallet":
        """
        Derivation from Path.

        :param path: Derivation path.
        :type path: str, Derivation

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_xprivate_key(xprivate_key="xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if isinstance(path, Derivation):
            path = str(path)
        elif str(path)[0:2] != "m/":
            raise ValueError("Bad path, please insert like this type of path \"m/0'/0\"!, not: %r" % ( path ))

        for index in path.lstrip("m/").split("/"):
            if "'" in index:
                self._derive_key_by_index(int(index[:-1]) + BIP32KEY_HARDEN)
                self._path += str("/" + index)
            else:
                self._derive_key_by_index(int(index))
                self._path += str("/" + index)
        return self

    def from_index(self, index: int, hardened: bool = False) -> "HDWallet":
        """
        Derivation from Index.

        :param index: Derivation index.
        :type index: int
        :param hardened: Hardened address, default to ``False``.
        :type hardened: bool

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_xprivate_key(xprivate_key="xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF")
        >>> hdwallet.from_index(index=44, hardened=True)
        >>> hdwallet.from_index(index=0, hardened=True)
        >>> hdwallet.from_index(index=0, hardened=True)
        >>> hdwallet.from_index(index=0)
        >>> hdwallet.from_index(index=0)
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        """

        if not isinstance(index, int):
            raise ValueError("Bad index, Please import only integer number!")

        if hardened:
            self._path += ("/%d'" % index)
            self._derive_key_by_index(index + BIP32KEY_HARDEN)
        else:
            self._path += ("/%d" % index)
            return self._derive_key_by_index(index)

    def _derive_key_by_index(self, index) -> Optional["HDWallet"]:

        if not self._root_private_key and not self._root_public_key:
            raise ValueError("You can't drive this master key.")

        i_str = struct.pack(">L", index)
        if index & BIP32KEY_HARDEN:
            if self._key is None:
                raise DerivationError("Hardened derivation path is invalid for xpublic key.")
            data = b"\0" + self._key.to_string() + i_str
        else:
            data = unhexlify(self.public_key()) + i_str

        if not self._chain_code:
            raise ValueError("You can't drive xprivate_key and private_key.")

        i = hmac.new(self._chain_code, data, hashlib.sha512).digest()
        il, ir = i[:32], i[32:]

        il_int = string_to_int(il)
        if il_int > CURVE_ORDER:
            return None

        if self._key:
            pvt_int = string_to_int(self._key.to_string())
            k_int = (il_int + pvt_int) % CURVE_ORDER
            if k_int == 0:
                return None
            secret = (b"\0" * 32 + int_to_string(k_int))[-32:]

            self._private_key, self._chain_code, self._depth, self._index, self._parent_fingerprint = (
                secret, ir, (self._depth + 1), index, unhexlify(self.finger_print())
            )
            self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()
        else:
            key_point = S256Point.parse(unhexlify(self.public_key()))
            left_point = il_int * G
            total = key_point + left_point

            self._chain_code, self._depth, self._index, self._parent_fingerprint = (
                ir, (self._depth + 1), index, unhexlify(self.finger_print())
            )
            self._verified_key = ecdsa.VerifyingKey.from_string(
                total.sec(), curve=SECP256k1
            )
        return self

    @staticmethod
    def _deserialize_xprivate_key(xprivate_key: str, encoded: bool = True) -> tuple:
        decoded_xprivate_key = check_decode(xprivate_key) if encoded else xprivate_key
        if len(decoded_xprivate_key) != 78:  # 156
            raise ValueError("Invalid xprivate key.")
        return (
            decoded_xprivate_key[:4], decoded_xprivate_key[4:5],
            decoded_xprivate_key[5:9], decoded_xprivate_key[9:13],
            decoded_xprivate_key[13:45], decoded_xprivate_key[46:]
        )

    @staticmethod
    def _deserialize_xpublic_key(xpublic_key: str, encoded: bool = True) -> tuple:
        decoded_xpublic_key = check_decode(xpublic_key) if encoded else xpublic_key
        if len(decoded_xpublic_key) != 78:  # 156
            raise ValueError("Invalid xpublic key.")
        return (
            decoded_xpublic_key[:4], decoded_xpublic_key[4:5],
            decoded_xpublic_key[5:9], decoded_xpublic_key[9:13],
            decoded_xpublic_key[13:45], decoded_xpublic_key[45:]
        )

    @staticmethod
    def _serialize_xkeys(version: bytes, depth: bytes, parent_fingerprint: bytes, index: bytes,
                         chain_code: bytes, data: bytes, encoded: bool = True) -> Optional[str]:
        try:
            raw = (version + depth + parent_fingerprint + index + chain_code + data)
            return check_encode(raw) if encoded else raw.hex()
        except TypeError:
            return None

    def raw_sign(self, data, deterministic=True):
        # sig_key = SigningKey.from_string(self._private_key, curve=SECP256k1)
        sig_func = partial(self._key.sign_digest_deterministic, hashfunc=sha256) if deterministic else self._key.sign_digest
        r, s, order = sig_func(data, sigencode=lambda *x: x)
        if s < 0x01:
            raise ValueError('Too low s value for signature: {}'.format(s))
        # ref: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
        if s > highest_s:
            s = order - s
        if s.to_bytes(32, 'big')[0] > 0x7f:
            s = int.from_bytes(b'\x00' + s.to_bytes(32, 'big'), 'big')
        if r.to_bytes(32, 'big')[0] > 0x7f:
            r = int.from_bytes(b'\x00' + r.to_bytes(32, 'big'), 'big')
        return r, s, order

    def sign(self, data, deterministic=True):
        return sigencode_der(*self.raw_sign(data, deterministic))

    def root_xprivate_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get Root XPrivate Key.

        :param encoded: Encoded root xprivate key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPrivate Key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.root_xprivate_key()
        "xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF"
        """

        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PRIVATE_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        if not self._i:
            return None
        secret_key, chain_code = self._i[:32], self._i[32:]
        depth = bytes(bytearray([self._root_depth]))
        parent_fingerprint = self._root_parent_fingerprint
        index = struct.pack(">L", self._root_index)
        data = b"\x00" + secret_key
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def root_xpublic_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get Root XPublic Key.

        :param encoded: Encoded root xpublic key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPublic Key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.root_xpublic_key()
        "xpub661MyMwAqRbcGSTjb2Mp3Sb4STUDhD2x986ubXKjQa2QsFTCVqzdA98qeZjcncHT1AaZcMSjiP1HJ16jH97q72RwyFfiNhmG8zQ6KBB5PaQ"
        """

        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PUBLIC_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        if self._root_public_key:
            data, chain_code = (
                self._root_public_key[0], self._root_public_key[1]
            )
        elif not self._i:
            return None
        else:
            secret_key, chain_code = self._i[:32], self._i[32:]
            data = unhexlify(self.public_key(private_key=secret_key.hex()))
        depth = bytes(bytearray([self._root_depth]))
        parent_fingerprint = self._root_parent_fingerprint
        index = struct.pack(">L", self._root_index)
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xprivate_key(self, encoded=True) -> Optional[str]:
        """
        Get XPrivate Key.

        :param encoded: Encoded xprivate key, default to ``True``.
        :type encoded: bool

        :returns: str -- Root XPrivate Key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.xprivate_key()
        "xprvA3BYGWQ9FmhyaNRRXB2f1LphNPnaY9T6gngw4BaTbkFtscSH4RCuJhgWUSKs9S6ciGioHd4TX4UeyUg53MkfN9Xh38xkS1j2Wb9YKsYpJHQ"
        """

        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PRIVATE_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        if self.private_key() is None:
            return None
        data = b"\x00" + unhexlify(self.private_key())
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def xpublic_key(self, encoded: bool = True) -> Optional[str]:
        """
        Get XPublic Key.

        :param encoded: Encoded xpublic key, default to ``True``.
        :type encoded: bool

        :returns: str -- XPublic Key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_entropy(entropy="ee535b143b0d9d1f87546f9df0d06b1a")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.xpublic_key()
        "xpub6GAtg1w369GGnrVtdCZfNUmRvRd4wcAx41cXrZz5A5nskQmRbxX9rVzzKiRU4JruirBrfm4KQXNSU7GfqL1tzZWpZYe9Zo4xKGJYohWoQe7"
        """

        if self._semantic is None:
            return None
        version = self._cryptocurrency.EXTENDED_PUBLIC_KEY.__getattribute__(
            self._semantic.upper()
        )
        if version is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} is not implemented for {self._cryptocurrency.NAME} {self._cryptocurrency.NETWORK} cryptocurrency."
            )
        depth = bytes(bytearray([self._depth]))
        parent_fingerprint = self._parent_fingerprint
        index = struct.pack(">L", self._index)
        chain_code = self._chain_code
        data = unhexlify(self.public_key())
        return self._serialize_xkeys(
            _unhexlify(version), depth, parent_fingerprint, index, chain_code, data, encoded
        )

    def clean_derivation(self) -> "HDWallet":
        """
        Clean derivation Path or Indexes.

        :returns: HDWallet -- Hierarchical Deterministic Wallet instance.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_xprivate_key(xprivate_key="xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.path()
        "m/44'/0'/0'/0/0"
        >>> hdwallet.clean_derivation()
        <hdwallet.hdwallet.HDWallet object at 0x000001E8BFB98D60>
        >>> hdwallet.path()
        None
        """

        if self._root_private_key:
            self._path, self._path_class, self._depth, self._parent_fingerprint, self._index = (
                "m", "m", 0, b"\0\0\0\0", 0
            )
            self._private_key, self._chain_code = self._root_private_key
            self._key = ecdsa.SigningKey.from_string(self._private_key, curve=SECP256k1)
            self._verified_key = self._key.get_verifying_key()
        elif self._root_public_key:
            self._path, self._path_class, self._depth, self._parent_fingerprint, self._index = (
                "m", "m", 0, b"\0\0\0\0", 0
            )
            self._chain_code = self._root_public_key[1]
            self._verified_key = ecdsa.VerifyingKey.from_string(
                self._root_public_key[0], curve=SECP256k1
            )
        return self

    def uncompressed(self, compressed: Optional[str] = None) -> str:
        """
        Get Uncommpresed Public Key.

        :param compressed: Compressed public key, default to ``None``.
        :type compressed: str

        :returns: str -- Uncommpresed public key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.uncompressed()
        "f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a875f63285a539213ac241fc4a88e7137ba1c8d897b1c1e5efb81bfc6b45a22d40"
        """

        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        public_key = unhexlify(compressed) if compressed else unhexlify(self.compressed())
        x = int.from_bytes(public_key[1:33], byteorder='big')
        y_sq = (pow(x, 3, p) + 7) % p
        y = pow(y_sq, (p + 1) // 4, p)
        if y % 2 != public_key[0] % 2:
            y = p - y
        y = y.to_bytes(32, byteorder='big')
        return (public_key[1:33] + y).hex()

    def compressed(self, uncompressed: Optional[str] = None) -> str:
        """
        Get Compresed Public Key.

        :param uncompressed: Uncompressed public key, default to ``None``.
        :type uncompressed: str

        :returns: str -- Commpresed public key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.compressed()
        "02f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a8"
        """

        _verified_key = ecdsa.VerifyingKey.from_string(
            unhexlify(uncompressed), curve=SECP256k1
        ) if uncompressed else self._verified_key
        padx = (b"\0" * 32 + int_to_string(
            _verified_key.pubkey.point.x()))[-32:]
        if _verified_key.pubkey.point.y() & 1:
            ck = b"\3" + padx
        else:
            ck = b"\2" + padx
        return hexlify(ck).decode()

    def private_key(self) -> str:
        """
        Get Private Key.

        :returns: str -- Private key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.private_key()
        "6cd78b0d69eab1a47bfa53a52b9d8c4331e858b5d7a599270a95d9735fdb0b94"
        """

        return hexlify(self._key.to_string()).decode() if self._key else None

    def public_key(self, compressed: bool = True, private_key: Optional[str] = None) -> str:
        """
        Get Public Key.

        :param compressed: Compressed public key, default to ``True``.
        :type compressed: bool
        :param private_key: Private key hex string, default to ``None``.
        :type private_key: str

        :returns: str -- Public key.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.public_key()
        "02f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a8"
        """

        if private_key:
            key = ecdsa.SigningKey.from_string(
                unhexlify(private_key), curve=SECP256k1)
            verified_key = key.get_verifying_key()
            padx = (b"\0" * 32 + int_to_string(
                verified_key.pubkey.point.x()))[-32:]
            if verified_key.pubkey.point.y() & 1:
                ck = b"\3" + padx
            else:
                ck = b"\2" + padx
            return hexlify(ck).decode() if compressed else self.uncompressed(compressed=hexlify(ck).decode())
        return self.compressed() if compressed else self.uncompressed()

    def strength(self) -> Optional[int]:
        """
        Get Entropy strength.

        :returns: int -- Entropy strength.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.strength()
        160
        """

        return self._strength if self._strength else None

    def entropy(self) -> Optional[str]:
        """
        Get Entropy hex string.

        :returns: str -- Entropy hex string.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.entropy()
        "f24afe7fc1418815ee7fd256beb55518e7c34ecd"
        """

        return hexlify(self._entropy).decode() if self._entropy else None

    def mnemonic(self) -> Optional[str]:
        """
        Get Mnemonic words.

        :returns: str -- Mnemonic words.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash")
        >>> hdwallet.mnemonic()
        "venture fitness paper little blush april rigid where find volcano fetch crack label polar dash"
        """

        return unicodedata.normalize("NFKD", self._mnemonic) if self._mnemonic else None

    def passphrase(self) -> Optional[str]:
        """
        Get Mnemonic passphrase.

        :returns: str -- Mnemonic passphrase.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.passphrase()
        "meherett"
        """

        return str(self._passphrase) if self._passphrase else None

    def language(self) -> Optional[str]:
        """
        Get Mnemonic language.

        :returns: str -- Mnemonic language.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.language()
        "english"
        """

        return str(self._language) if self._language else None

    def cryptocurrency(self) -> Optional[str]:
        """
        Get Cryptocurrency name.

        :returns: str -- Cryptocurrency name.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.cryptocurrency()
        "Bitcoin"
        """

        return str(self._cryptocurrency.NAME)

    def symbol(self) -> Optional[str]:
        """
        Get Cryptocurrency symbol.

        :returns: str -- Cryptocurrency symbol.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.symbol()
        "BTC"
        """

        return str(self._cryptocurrency.SYMBOL)

    def semantic(self) -> Optional[str]:
        """
        Get Extended semantic.

        :returns: str -- Extended semantic.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.semantic()
        "p2pkh"
        """

        return self._semantic if self._semantic else None

    def network(self) -> Optional[str]:
        """
        Get Cryptocurrency network type.

        :returns: str -- Cryptocurrency network type.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.network()
        "mainnet"
        """

        return str(self._cryptocurrency.NETWORK)

    def seed(self) -> Optional[str]:
        """
        Get Seed hex string.

        :returns: str -- Seed hex string.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.seed()
        "8d5f4fe5b81a6a6a18b08603b6b3f59df9f4bbb25d10c55d23e0cbdc5ee385e5fddad9d7e6114f11afdec45928328081f9a598151a7613dc5f5a0c16a4612aa4"
        """

        return hexlify(self._seed).decode() if self._seed else None

    def path(self) -> Optional[str]:
        """
        Get Derivation path.

        :returns: str -- Drivation path.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.path()
        "m/44'/0'/0'/0/0"
        """

        return str(self._path) if not self._path == "m" else None

    def chain_code(self) -> Optional[str]:
        """
        Get Chain code.

        :returns: str -- Chain code.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.chain_code()
        "ed45793b944d1f22522f2d6f48c487029fae2cfcd999ed23087a148bcdda6314"
        """

        return hexlify(self._chain_code).decode() if self._chain_code else None

    def hash(self, private_key: str = None):
        """
        Get Public Key Hash.

        :returns: str -- Identifier.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.hash()
        "4d887566d408dfe5ea8090f2b716f9639523ca89"
        """

        return hexlify(ripemd160(sha256(unhexlify(self.public_key(
            private_key=private_key if private_key else self.private_key()
        ))).digest())).decode("utf-8")

    def finger_print(self) -> str:
        """
        Get Finger print.

        :returns: str -- Finger print.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.finger_print()
        "4d887566"
        """

        return self.hash(self.private_key())[:8]

    def p2pkh_address(self) -> str:
        """
        Get Pay to Public Key Hash (P2PKH) address.

        :returns: str -- P2PKH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2pkh_address()
        "184xW5gWDnhS7LriL2JAZs1XGTJjimz7pq"
        """

        if self._cryptocurrency.SYMBOL in ["ETH", "ETHTEST"]:
            keccak_256 = keccak.new(digest_bits=256)
            keccak_256.update(unhexlify(self.uncompressed()))
            address = keccak_256.hexdigest()[24:]
            return checksum_encode(address, crypto="eth")
        elif self._cryptocurrency.SYMBOL in ["XDC", "XDCTEST"]:
            keccak_256 = keccak.new(digest_bits=256)
            keccak_256.update(unhexlify(self.uncompressed()))
            address = keccak_256.hexdigest()[24:]
            return checksum_encode(address, crypto="xdc")
        elif self._cryptocurrency.SYMBOL in ["TRX"]:
            keccak_256 = keccak.new(digest_bits=256)
            keccak_256.update(unhexlify(self.uncompressed()))
            address = keccak_256.hexdigest()[24:]
            network_hash160_bytes = _unhexlify(self._cryptocurrency.PUBLIC_KEY_ADDRESS) + bytearray.fromhex(address)
            return ensure_string(base58.b58encode_check(network_hash160_bytes))
        elif self._cryptocurrency.SYMBOL in ["XRP"]:
            XRPL_ALPHABET = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
            compressed_public_key = unhexlify(self.compressed())
            public_key_hash = hashlib.new("ripemd160", sha256(compressed_public_key).digest()).digest()
            network_hash160_bytes = _unhexlify(self._cryptocurrency.PUBLIC_KEY_ADDRESS) + public_key_hash
            return ensure_string(base58.b58encode_check(network_hash160_bytes, alphabet=XRPL_ALPHABET))

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = ripemd160(sha256(compressed_public_key).digest())
        network_hash160_bytes = _unhexlify(self._cryptocurrency.PUBLIC_KEY_ADDRESS) + public_key_hash
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2sh_address(self) -> str:
        """
        Get Pay to Script Hash (P2SH) address.

        :returns: str -- P2SH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2sh_address()
        "3Jp6ad4ErhibQmhSRfavbPRiUyg2xTTT4j"
        """

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hexlify(ripemd160(sha256(compressed_public_key).digest())).decode("utf-8")
        public_key_hash_script = unhexlify("76a914" + public_key_hash + "88ac")
        script_hash = ripemd160(sha256(public_key_hash_script).digest())
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2wpkh_address(self) -> Optional[str]:
        """
        Get Pay to Witness Public Key Hash (P2WPKH) address.

        :returns: str -- P2WPKH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2wpkh_address()
        "bc1qfky82ek5pr07t65qjretw9hevw2j8j5fdrn5hc"
        """

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = ripemd160(sha256(compressed_public_key).digest())
        segwit = self._cryptocurrency.SEGWIT_ADDRESS
        if segwit.HRP is None:
            return None
        return ensure_string(encode(segwit.HRP, segwit.VERSION, public_key_hash))

    def p2wpkh_in_p2sh_address(self) -> Optional[str]:
        """
        Get P2WPKH nested in P2SH address.

        :returns: str -- P2WPKH nested in P2SH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2wpkh_in_p2sh_address()
        "3CCrxPrHNa6ePbnB7qjh7S3vaPx9qiLc3e"
        """

        compressed_public_key = unhexlify(self.compressed())
        public_key_hash = hexlify(ripemd160(sha256(compressed_public_key).digest())).decode("utf-8")
        script_hash = ripemd160(sha256(unhexlify("0014" + public_key_hash)).digest())
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def p2wsh_address(self) -> Optional[str]:
        """
        Get Pay to Witness Script Hash (P2WSH) address.

        :returns: str -- P2WSH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2wsh_address()
        "bc1qaj2xa9j6eegcxls3y8p6erw6vdgdxynasrd4hl3xuctht5edu3msdeshgf"
        """

        compressed_public_key = unhexlify("5121" + self.compressed() + "51ae")
        script_hash = sha256(compressed_public_key).digest()
        segwit = self._cryptocurrency.SEGWIT_ADDRESS
        if segwit.HRP is None:
            return None
        return ensure_string(encode(segwit.HRP, segwit.VERSION, script_hash))

    def p2wsh_in_p2sh_address(self) -> Optional[str]:
        """
        Get P2WSH nested in P2SH address.

        :returns: str -- P2WSH nested in P2SH address.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.p2wsh_in_p2sh_address()
        "38YMonfh2yLFRViLrM2kdvZx8ctcp1vbbV"
        """

        compressed_public_key = unhexlify("5121" + self.compressed() + "51ae")
        script_hash = unhexlify("0020" + sha256(compressed_public_key).hexdigest())
        script_hash = ripemd160(sha256(script_hash).digest())
        network_hash160_bytes = _unhexlify(self._cryptocurrency.SCRIPT_ADDRESS) + script_hash
        if self._cryptocurrency.SEGWIT_ADDRESS.HRP is None:
            return None
        return ensure_string(base58.b58encode_check(network_hash160_bytes))

    def wif(self) -> Optional[str]:
        """
        Get Wallet Important Format.

        :returns: str -- Wallet Important Format.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.wif()
        "KzsHWUJsrTWUUhBGPfMMxLLydiH7NhEn6z7mKHXD5qNkUWaC4TEn"
        """

        return check_encode(_unhexlify(self._cryptocurrency.WIF_SECRET_KEY) + self._key.to_string() + b"\x01") if self._key else None

    def dumps(self) -> dict:
        """
        Get All HDWallet imformations.

        :returns: dict -- All HDWallet imformations.

        >>> from hdwallet import HDWallet
        >>> from hdwallet.symbols import BTC
        >>> hdwallet = HDWallet(symbol=BTC)
        >>> hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> hdwallet.from_path(path="m/44'/0'/0'/0/0")
        >>> hdwallet.dumps()
        {'cryptocurrency': 'Bitcoin', 'symbol': 'BTC', 'network': 'mainnet', 'strength': 160, 'entropy': 'f24afe7fc1418815ee7fd256beb55518e7c34ecd', 'mnemonic': 'venture fitness paper little blush april rigid where find volcano fetch crack label polar dash', 'language': 'english', 'passphrase': None, 'seed': '8d5f4fe5b81a6a6a18b08603b6b3f59df9f4bbb25d10c55d23e0cbdc5ee385e5fddad9d7e6114f11afdec45928328081f9a598151a7613dc5f5a0c16a4612aa4', 'root_xprivate_key': 'xprv9s21ZrQH143K3xPGUzpogJeKtRdjHkK6muBJo8v7rEVRzT83xJgNcLpMoJXUf9wJFKfuHR4SGvfgdShh4t9VmjjrE9usBunK3LfNna31LGF', 'root_xpublic_key': 'xpub661MyMwAqRbcGSTjb2Mp3Sb4STUDhD2x986ubXKjQa2QsFTCVqzdA98qeZjcncHT1AaZcMSjiP1HJ16jH97q72RwyFfiNhmG8zQ6KBB5PaQ', 'xprivate_key': 'xprvA3BYGWQ9FmhyaNRRXB2f1LphNPnaY9T6gngw4BaTbkFtscSH4RCuJhgWUSKs9S6ciGioHd4TX4UeyUg53MkfN9Xh38xkS1j2Wb9YKsYpJHQ', 'xpublic_key': 'xpub6GAtg1w369GGnrVtdCZfNUmRvRd4wcAx41cXrZz5A5nskQmRbxX9rVzzKiRU4JruirBrfm4KQXNSU7GfqL1tzZWpZYe9Zo4xKGJYohWoQe7', 'uncompressed': 'f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a875f63285a539213ac241fc4a88e7137ba1c8d897b1c1e5efb81bfc6b45a22d40', 'compressed': '02f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a8', 'chain_code': 'ed45793b944d1f22522f2d6f48c487029fae2cfcd999ed23087a148bcdda6314', 'private_key': '6cd78b0d69eab1a47bfa53a52b9d8c4331e858b5d7a599270a95d9735fdb0b94', 'public_key': '02f93f58b97c3bb616645c3dda256ec946d87c45baf531984c022dd0fd1503b0a8', 'wif': 'KzsHWUJsrTWUUhBGPfMMxLLydiH7NhEn6z7mKHXD5qNkUWaC4TEn', 'identifier': '4d887566d408dfe5ea8090f2b716f9639523ca89', 'finger_print': '4d887566', 'path': "m/44'/0'/0'/0/0", 'addresses': {'p2pkh': '184xW5gWDnhS7LriL2JAZs1XGTJjimz7pq', 'p2sh': '3Jp6ad4ErhibQmhSRfavbPRiUyg2xTTT4j', 'p2wpkh': 'bc1qfky82ek5pr07t65qjretw9hevw2j8j5fdrn5hc', 'p2wpkh_in_p2sh': '3CCrxPrHNa6ePbnB7qjh7S3vaPx9qiLc3e', 'p2wsh': 'bc1qaj2xa9j6eegcxls3y8p6erw6vdgdxynasrd4hl3xuctht5edu3msdeshgf', 'p2wsh_in_p2sh': '38YMonfh2yLFRViLrM2kdvZx8ctcp1vbbV'}}
        """

        return dict(
            cryptocurrency=self.cryptocurrency(),
            symbol=self.symbol(),
            network=self.network(),
            strength=self.strength(),
            entropy=self.entropy(),
            mnemonic=self.mnemonic(),
            language=self.language(),
            passphrase=self.passphrase(),
            seed=self.seed(),
            root_xprivate_key=self.root_xprivate_key(),
            # root_xprivate_key_hex=self.root_xprivate_key(encoded=False),
            root_xpublic_key=self.root_xpublic_key(),
            # root_xpublic_key_hex=self.root_xpublic_key(encoded=False),
            xprivate_key=self.xprivate_key(),
            # xprivate_key_hex=self.xprivate_key(encoded=False),
            xpublic_key=self.xpublic_key(),
            # xpublic_key_hex=self.xpublic_key(encoded=False),
            uncompressed=self.uncompressed(),
            compressed=self.compressed(),
            chain_code=self.chain_code(),
            private_key=self.private_key(),
            public_key=self.public_key(),
            wif=self.wif(),
            finger_print=self.finger_print(),
            semantic=self.semantic(),
            path=self.path(),
            hash=self.hash(),
            addresses=dict(
                p2pkh=self.p2pkh_address(),
                p2sh=self.p2sh_address(),
                p2wpkh=self.p2wpkh_address(),
                p2wpkh_in_p2sh=self.p2wpkh_in_p2sh_address(),
                p2wsh=self.p2wsh_address(),
                p2wsh_in_p2sh=self.p2wsh_in_p2sh_address()
            )
        )


class BIP32HDWallet(HDWallet):
    """
    BIP32 Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, default to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param purpose: Purpose index, default to ``0``.
    :type purpose: int, tuple
    :param coin_type: Coin type, default to ``0``.
    :type coin_type: int, tuple
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple

    :returns: BIP32HDWallet -- BIP32 Hierarchical Deterministic Wallet instance.

    >>> from hdwallet import BIP32HDWallet
    >>> from hdwallet.cryptocurrencies import QtumMainnet
    >>> bip32_hdwallet: BIP32HDWallet = BIP32HDWallet(cryptocurrency=QtumMainnet, purpose=0, coin_type=0, account=0, change=False, address=0)
    <hdwallet.hdwallet.BIP32HDWallet object at 0x000001EBC58E9F70>
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 purpose: Union[int, Tuple[int, bool]] = 0,
                 coin_type: Union[int, Tuple[int, bool]] = 0,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super(BIP32HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic="p2pkh"
        )

        self._from_class = True
        self._path_class = BIP32Derivation(
            cryptocurrency=self._cryptocurrency,
            purpose=purpose, coin_type=coin_type,
            account=account, change=change, address=address
        )

    def address(self) -> str:
        """
        Get Pay to Public Key Hash (P2PKH) address.

        :returns: str -- P2PKH address.

        >>> from hdwallet import BIP32HDWallet
        >>> from hdwallet.symbols import BTC
        >>> bip32_hdwallet: BIP32HDWallet = BIP32HDWallet(symbol=BTC, purpose=44, coin_type=0, account=0, change=False, address=0)
        >>> bip32_hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> bip32_hdwallet.address()
        "184xW5gWDnhS7LriL2JAZs1XGTJjimz7pq"
        """

        return self.p2pkh_address()


class BIP44HDWallet(HDWallet):
    """
    BIP44 Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, default to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple

    :returns: BIP44HDWallet -- BIP44 Hierarchical Deterministic Wallet instance.

    >>> from hdwallet import BIP44HDWallet
    >>> from hdwallet.cryptocurrencies import QtumMainnet
    >>> bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=QtumMainnet, account=0, change=False, address=0)
    <hdwallet.hdwallet.BIP44HDWallet object at 0x000001EBC58E9F70>
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super(BIP44HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic="p2pkh"
        )

        self._from_class = True
        self._path_class = BIP44Derivation(
            cryptocurrency=self._cryptocurrency, account=account, change=change, address=address
        )

    def address(self) -> str:
        """
        Get Pay to Public Key Hash (P2PKH) address.

        :returns: str -- P2PKH address.

        >>> from hdwallet import BIP44HDWallet
        >>> from hdwallet.symbols import BTC
        >>> bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(symbol=BTC, account=0, change=False, address=0)
        >>> bip44_hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> bip44_hdwallet.address()
        "184xW5gWDnhS7LriL2JAZs1XGTJjimz7pq"
        """

        return self.p2pkh_address()


class BIP49HDWallet(HDWallet):
    """
    BIP49 Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, default to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple

    :returns: BIP49HDWallet -- BIP49 Hierarchical Deterministic Wallet instance.

    >>> from hdwallet import BIP49HDWallet
    >>> from hdwallet.cryptocurrencies import QtumMainnet
    >>> bip49_hdwallet: BIP49HDWallet = BIP49HDWallet(cryptocurrency=QtumMainnet, account=0, change=False, address=0)
    <hdwallet.hdwallet.BIP49HDWallet object at 0x000001EBC58E9F70>
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super(BIP49HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic="p2wpkh_in_p2sh"
        )

        self._from_class = True
        self._path_class = BIP49Derivation(
            cryptocurrency=self._cryptocurrency, account=account, change=change, address=address
        )

    def address(self) -> str:
        """
        Get P2WPKH nested in P2SH address.

        :returns: str -- P2PKH In P2SH address.

        >>> from hdwallet import BIP49HDWallet
        >>> from hdwallet.symbols import BTC
        >>> bip49_hdwallet: BIP49HDWallet = BIP49HDWallet(symbol=BTC, account=0, change=False, address=0)
        >>> bip49_hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> bip49_hdwallet.address()
        "3HtjZPoiUh9DA3kzQL9XZ29aFdCzouWB6T"
        """

        return self.p2wpkh_in_p2sh_address()


class BIP84HDWallet(HDWallet):
    """
    BIP84 Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, default to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param account: Account index, default to ``0``.
    :type account: int, tuple
    :param change: Change addresses, default to ``False``.
    :type change: bool
    :param address: Address index, default to ``0``.
    :type address: int, tuple

    :returns: BIP84HDWallet -- BIP84 Hierarchical Deterministic Wallet instance.

    >>> from hdwallet import BIP84HDWallet
    >>> from hdwallet.cryptocurrencies import QtumMainnet
    >>> bip84_hdwallet: BIP84HDWallet = BIP84HDWallet(cryptocurrency=QtumMainnet, account=0, change=False, address=0)
    <hdwallet.hdwallet.BIP84HDWallet object at 0x000001EBC58E9F70>
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 account: Union[int, Tuple[int, bool]] = 0,
                 change: bool = False,
                 address: Union[int, Tuple[int, bool]] = 0):
        super(BIP84HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic="p2wpkh"
        )

        self._from_class = True
        self._path_class = BIP84Derivation(
            cryptocurrency=self._cryptocurrency, account=account, change=change, address=address
        )

    def address(self) -> str:
        """
        Get Pay to Witness Public Key Hash (P2WPKH) address.

        :returns: str -- Pay to Witness Public Key Hash (P2WPKH) address.

        >>> from hdwallet import BIP84HDWallet
        >>> from hdwallet.symbols import BTC
        >>> bip84_hdwallet: BIP84HDWallet = BIP84HDWallet(symbol=BTC, account=0, change=False, address=0)
        >>> bip84_hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> bip84_hdwallet.address()
        "bc1qs95czhkhawdq958gjscrw4mh6amu2ysx20w86d"
        """

        return self.p2wpkh_address()


class BIP141HDWallet(HDWallet):
    """
    BIP141 Hierarchical Deterministic Wallet

    :param symbol: Cryptocurrency symbol, defaults to ``BTC``.
    :type symbol: str
    :param cryptocurrency: Cryptocurrency instance, defaults to ``None``.
    :type cryptocurrency: Cryptocurrency
    :param path: Derivation path.
    :type path: str
    :param semantic: Extended semantic, defaults to ``P2WPKH``.
    :type semantic: str

    :returns: BIP141HDWallet -- BIP141 Hierarchical Deterministic Wallet instance.

    >>> from hdwallet import BIP141HDWallet
    >>> from hdwallet.cryptocurrencies import QtumMainnet
    >>> bip141_hdwallet: BIP141HDWallet = BIP141HDWallet(cryptocurrency=QtumMainnet, path="m/0/0", semantic="p2wpkh")
    <hdwallet.hdwallet.BIP141HDWallet object at 0x000001EBC58E9F70>
    """

    def __init__(self, symbol: str = "BTC", cryptocurrency: Any = None,
                 path: Union[str, Derivation] = None, semantic: str = "p2wpkh"):
        super(BIP141HDWallet, self).__init__(
            symbol=symbol, cryptocurrency=cryptocurrency, semantic=semantic
        )

        self._from_class = True
        self._path_class = BIP141Derivation(
            cryptocurrency=self._cryptocurrency, path=path, semantic=semantic
        )

    def address(self) -> str:
        """
        Get P2WPKH, P2WPKH_IN_P2SH, P2WSH or P2WPKH_IN_P2SH addresses by semantic.

        :returns: str -- P2WPKH, P2WPKH_IN_P2SH, P2WSH or P2WPKH_IN_P2SH addresses.

        >>> from hdwallet import BIP141HDWallet
        >>> from hdwallet.symbols import BTC
        >>> bip141_hdwallet: BIP141HDWallet = BIP141HDWallet(symbol=BTC, path="m/44'/0'/0'/0/0", semantic="p2wsh")
        >>> bip141_hdwallet.from_mnemonic(mnemonic="venture fitness paper little blush april rigid where find volcano fetch crack label polar dash", passphrase="meherett")
        >>> bip141_hdwallet.address()
        "bc1qaj2xa9j6eegcxls3y8p6erw6vdgdxynasrd4hl3xuctht5edu3msdeshgf"
        """

        if self._path_class.SEMANTIC == "p2wpkh":
            return self.p2wpkh_address()
        elif self._path_class.SEMANTIC == "p2wpkh_in_p2sh":
            return self.p2wpkh_in_p2sh_address()
        elif self._path_class.SEMANTIC == "p2wsh":
            return self.p2wsh_address()
        elif self._path_class.SEMANTIC == "p2wsh_in_p2sh":
            return self.p2wsh_in_p2sh_address()
        else:
            raise SemanticError(
                "Wrong extended semantic",
                "choose only the following options 'p2wpkh', 'p2wpkh_in_p2sh', 'p2wsh' or 'p2wsh_in_p2sh' semantics."
            )
