#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union, List, Type
)
from hashlib import sha256

import hmac
import hashlib
import struct

from ..libs.ripemd160 import ripemd160
from ..libs.base58 import check_decode
from ..eccs import (
    IPoint, IPublicKey, IPrivateKey, IEllipticCurveCryptography, KholawEd25519PrivateKey
)
from ..seeds import ISeed
from ..derivations import (
    IDerivation, CustomDerivation
)
from ..addresses import (
    P2PKHAddress, P2SHAddress, P2TRAddress, P2WPKHAddress, P2WPKHInP2SHAddress, P2WSHAddress, P2WSHInP2SHAddress
)
from ..consts import (
    PUBLIC_KEY_TYPES, WIF_TYPES
)
from ..cryptocurrencies import Bitcoin
from ..crypto import hmac_sha512
from ..wif import (
    private_key_to_wif, wif_to_private_key, get_wif_type
)
from ..keys import (
    serialize, deserialize, is_valid_key, is_root_key
)
from ..exceptions import (
    Error, AddressError, DerivationError, XPrivateKeyError, XPublicKeyError, PublicKeyError, PrivateKeyError, SeedError, WIFError
)
from ..utils import (
    get_bytes, get_hmac, bytes_to_integer, integer_to_bytes, bytes_to_string, reset_bits, set_bits
)
from .ihd import IHD


class BIP32HD(IHD):

    _seed: Optional[bytes] = None
    _hmac: Optional[bytes] = None
    _root_private_key: Optional[IPrivateKey] = None
    _root_chain_code: Optional[bytes] = None
    _root_public_key: Optional[IPublicKey] = None
    _private_key: Optional[IPrivateKey] = None
    _chain_code: Optional[bytes] = None
    _public_key: Optional[IPublicKey] = None
    _public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED
    _wif_type: str = WIF_TYPES.WIF_COMPRESSED
    _wif_prefix: Optional[int] = None
    _fingerprint: Optional[bytes] = None
    _parent_fingerprint: Optional[bytes] = None
    _strict: Optional[bool] = None
    _derivation: IDerivation
    _root_depth: int = 0
    _root_index: int = 0
    _depth: int = 0
    _index: int = 0

    def __init__(
        self, ecc: Type[IEllipticCurveCryptography], public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED, **kwargs
    ) -> None:
        """
        Initializes a new instance of the BIP32HD class.

        :param ecc: The elliptic curve cryptography class to be used. Must be a type of `IEllipticCurveCryptography`.
        :type ecc: Type[IEllipticCurveCryptography]
        :param public_key_type: The type of public key to be used, either `PUBLIC_KEY_TYPES.COMPRESSED` or
                                `PUBLIC_KEY_TYPES.UNCOMPRESSED`. Defaults to `PUBLIC_KEY_TYPES.COMPRESSED`.
        :type public_key_type: str
        :param kwargs: Additional keyword arguments for custom derivation paths and indexes.
        :type kwargs: dict

        :return: None
        """

        super(BIP32HD, self).__init__(**kwargs)

        self._ecc: IEllipticCurveCryptography = ecc.__call__()
        if public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            self._wif_type = WIF_TYPES.WIF
        elif public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            self._wif_type = WIF_TYPES.WIF_COMPRESSED
        else:
            raise Error(
                f"Invalid {self.name()} public key type",
                expected=PUBLIC_KEY_TYPES.get_types(),
                got=public_key_type
            )
        self._wif_prefix = kwargs.get("wif_prefix", None)
        self._public_key_type = public_key_type
        self._derivation = CustomDerivation(
            path=kwargs.get("path", None), indexes=kwargs.get("indexes", None)
        )

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the bip class.

        :return: The name of the bip class.
        :rtype: str
        """
        return "BIP32"

    def __update__(self) -> "BIP32HD":
        """
        Updates the BIP32HD instance by applying the current derivation path.

        :return: The updated instance of BIP32HD.
        :rtype: BIP32HD
        """

        self.from_derivation(derivation=self._derivation)
        return self

    def from_seed(self, seed: Union[bytes, str, ISeed], **kwargs) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given seed.

        :param seed: The seed to initialize the instance. It can be of type `bytes`, `str`, or `ISeed`.
        :type seed: Union[bytes, str, ISeed]
        :param kwargs: Additional keyword arguments.

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        try:
            self._seed = get_bytes(
                seed.seed() if isinstance(seed, ISeed) else seed
            )
        except ValueError as error:
            raise SeedError("Invalid seed data") from error

        if len(self._seed) < 16:
            raise Error("Invalid seed length", expected="< 16", got=len(self._seed))

        hmac_half_length: int = hashlib.sha512().digest_size // 2

        self._hmac: bytes = b""
        hmac_data: bytes = self._seed
        success: bool = False

        while not success:
            self._hmac = hmac.digest(
                get_hmac(ecc_name=self._ecc.NAME), hmac_data, "sha512"
            ) if hasattr(hmac, "digest") else hmac.new(
                get_hmac(ecc_name=self._ecc.NAME), hmac_data, hashlib.sha512
            ).digest()

            if self._ecc.NAME == "Kholaw-Ed25519":
                success = ((self._hmac[:hmac_half_length][31] & 0x20) == 0)
                if not success:
                    hmac_data = self._hmac
            else:
                private_key_class: IPrivateKey = self._ecc.PRIVATE_KEY
                success = private_key_class.is_valid_bytes(self._hmac[:hmac_half_length])
                if not success:
                    hmac_data = self._hmac

        def tweak_master_key_bits(data: bytes) -> bytes:

            data: bytearray = bytearray(data)
            data[0] = reset_bits(data[0], 0x07)
            data[31] = reset_bits(data[31], 0x80)
            data[31] = set_bits(data[31], 0x40)

            return bytes(data)

        if self._ecc.NAME == "Kholaw-Ed25519":
            kl_bytes, kr_bytes = (
                self._hmac[:hmac_half_length], self._hmac[hmac_half_length:]
            )
            kl_bytes = tweak_master_key_bits(kl_bytes)

            chain_code_bytes = hmac.digest(
                get_hmac(ecc_name=self._ecc.NAME), integer_to_bytes(0x01) + self._seed, "sha256"
            ) if hasattr(hmac, "digest") else hmac.new(
                get_hmac(ecc_name=self._ecc.NAME), integer_to_bytes(0x01) + self._seed, hashlib.sha256
            ).digest()

            self._root_private_key, self._root_chain_code = (
                self._ecc.PRIVATE_KEY.from_bytes(
                    (kl_bytes + kr_bytes)
                ), chain_code_bytes
            )
        else:
            self._root_private_key, self._root_chain_code = (
                self._ecc.PRIVATE_KEY.from_bytes(
                    self._hmac[:hmac_half_length]
                ), self._hmac[hmac_half_length:]
            )

        self._private_key, self._chain_code, self._parent_fingerprint = (
            self._root_private_key, self._root_chain_code, (integer_to_bytes(0x00) * 4)
        )
        self._root_public_key = self._root_private_key.public_key()
        self._public_key = self._root_public_key
        self._strict = True
        self.__update__()
        return self

    def from_xprivate_key(
        self, xprivate_key: str, encoded: bool = True, strict: bool = False
    ) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given extended private key (xprivate key).

        :param xprivate_key: The extended private key to initialize the instance. It should be a string.
        :type xprivate_key: str
        :param encoded: Indicates if the xprivate key is encoded. Defaults to True.
        :type encoded: bool
        :param strict: If set to True, enforces strict checking to ensure the xprivate key is a root key. Defaults to False.
        :type strict: bool

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        if not is_valid_key(key=xprivate_key, encoded=encoded):
            raise XPrivateKeyError("Invalid extended(x) private key")
        if len(check_decode(xprivate_key) if encoded else xprivate_key) not in [78, 110]:
            raise XPrivateKeyError("Invalid extended(x) private key")
        if not is_root_key(key=xprivate_key, encoded=encoded) and strict:
            raise XPrivateKeyError("Invalid root extended(x) private key")

        version, depth, parent_fingerprint, index, chain_code, key = deserialize(
            key=xprivate_key, encoded=encoded
        )
        self._root_chain_code = chain_code
        self._root_private_key = self._ecc.PRIVATE_KEY.from_bytes(key[1:])
        self._root_public_key = self._root_private_key.public_key()
        self._root_depth = depth
        self._parent_fingerprint = parent_fingerprint
        self._root_index = index
        self._chain_code = self._root_chain_code
        self._private_key = self._root_private_key
        self._public_key = self._root_public_key
        self._depth = self._root_depth
        self._index = self._root_index
        self._strict = is_root_key(
            key=xprivate_key, encoded=encoded
        )
        self.__update__()
        return self

    def from_xpublic_key(
        self, xpublic_key: str, encoded: bool = True, strict: bool = False
    ) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given extended public key (xpublic key).

        :param xpublic_key: The extended public key to initialize the instance. It should be a string.
        :type xpublic_key: str
        :param encoded: Indicates if the xpublic key is encoded. Defaults to True.
        :type encoded: bool
        :param strict: If set to True, enforces strict checking to ensure the xpublic key is a root key. Defaults to False.
        :type strict: bool

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        if not is_valid_key(key=xpublic_key, encoded=encoded):
            raise XPublicKeyError("Invalid extended(x) public key")
        if len(check_decode(xpublic_key) if encoded else xpublic_key) != 78:
            raise XPublicKeyError("Invalid extended(x) public key")
        if not is_root_key(key=xpublic_key, encoded=encoded) and strict:
            raise XPublicKeyError("Invalid root extended(x) public key")

        version, depth, parent_fingerprint, index, chain_code, key = deserialize(
            key=xpublic_key, encoded=encoded
        )
        self._root_chain_code = chain_code
        self._root_public_key = self._ecc.PUBLIC_KEY.from_bytes(key)
        self._root_depth = depth
        self._parent_fingerprint = parent_fingerprint
        self._root_index = index
        self._chain_code = self._root_chain_code
        self._public_key = self._root_public_key
        self._depth = self._root_depth
        self._index = self._root_index
        self._strict = is_root_key(
            key=xpublic_key, encoded=encoded
        )
        self.__update__()
        return self

    def from_wif(self, wif: str) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given Wallet Import Format (WIF) key.

        :param wif: The Wallet Import Format (WIF) key to initialize the instance.
        :type wif: str

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        if self._wif_prefix is None:
            raise WIFError("WIF prefix is required")

        if get_wif_type(wif=wif, wif_prefix=self._wif_prefix) == "wif-compressed":
            self._public_key_type: str = PUBLIC_KEY_TYPES.COMPRESSED
            self._wif_type: str = WIF_TYPES.WIF_COMPRESSED
        else:
            self._public_key_type: str = PUBLIC_KEY_TYPES.UNCOMPRESSED
            self._wif_type: str = WIF_TYPES.WIF
        self.from_private_key(private_key=wif_to_private_key(wif=wif, wif_prefix=self._wif_prefix))
        self._strict = None
        return self

    def from_private_key(self, private_key: str) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given private key.

        :param private_key: The private key to initialize the instance, represented as a string.
        :type private_key: str

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        try:
            self._private_key = self._ecc.PRIVATE_KEY.from_bytes(get_bytes(private_key))
            self._public_key = self._private_key.public_key()
            self._strict = None
            return self
        except ValueError as error:
            raise PrivateKeyError("Invalid private key data") from error

    def from_public_key(self, public_key: str) -> "BIP32HD":
        """
        Initializes the BIP32HD instance from the given public key.

        :param public_key: The public key to initialize the instance, represented as a string.
        :type public_key: str

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        try:
            self._public_key = self._ecc.PUBLIC_KEY.from_bytes(get_bytes(public_key))
            self._strict = None
            return self
        except ValueError as error:
            raise PublicKeyError("Invalid public key data") from error

    def from_derivation(self, derivation: IDerivation) -> "BIP32HD":
        """
        Initializes the BIP32HD instance using the specified derivation path.

        :param derivation: The derivation path to initialize the instance.
                           It must be an instance of `IDerivation`.
        :type derivation: IDerivation

        :return: The initialized BIP32HD instance.
        :rtype: BIP32HD
        """

        if not isinstance(derivation, IDerivation):
            raise DerivationError("Invalid derivation instance", expected=IDerivation, got=type(derivation))

        self._derivation = derivation
        for index in self._derivation.indexes():
            self.drive(index)
        return self

    def update_derivation(self, derivation: IDerivation) -> "BIP32HD":
        """
        Updates the derivation path for the BIP32HD instance.

        This method first cleans the current derivation path and then sets the new
        derivation path provided. It drives the instance through the new derivation path.

        :param derivation: The new derivation path to set. It must be an instance of `IDerivation`.
        :type derivation: IDerivation

        :return: The updated BIP32HD instance.
        :rtype: BIP32HD
        """

        self.clean_derivation()
        self.from_derivation(
            derivation=derivation
        )
        return self

    def clean_derivation(self) -> "BIP32HD":
        """
        Cleans the derivation path of the BIP32HD instance.

        :return: The cleaned BIP32HD instance.
        :rtype: BIP32HD
        """

        if self._root_private_key:
            self._private_key, self._chain_code, self._parent_fingerprint = (
                self._root_private_key, self._root_chain_code, (integer_to_bytes(0x00) * 4)
            )
            self._public_key = self._private_key.public_key()
            self._derivation.clean()
            self._depth = 0
        elif self._root_public_key:
            self._public_key, self._chain_code, self._parent_fingerprint = (
                self._root_public_key, self._root_chain_code, (integer_to_bytes(0x00) * 4)
            )
            self._derivation.clean()
            self._depth = 0
        return self

    def drive(self, index: int) -> Optional["BIP32HD"]:
        """
        Drives the BIP32HD instance forward along the derivation path by deriving a child key at the given index.

        :param index: The index to derive the child key.
        :type index: int

        :return: The updated BIP32HD instance with the derived child key, or None if the derivation fails.
        :rtype: Optional[BIP32HD]
        """

        hmac_half_length: int = hashlib.sha512().digest_size // 2

        if self._ecc.NAME == "Kholaw-Ed25519":
            index_bytes: bytes = integer_to_bytes(
                data=index, bytes_num=4, endianness="little"
            )
            if self._private_key:
                if index & 0x80000000:
                    if self._private_key is None:
                        raise DerivationError("Hardened derivation path is invalid for xpublic key")
                    z_hmac: bytes = hmac_sha512(self._chain_code, (
                        integer_to_bytes(0x00) + self._private_key.raw() + index_bytes
                    ))
                    _hmac: bytes = hmac_sha512(self._chain_code, (
                        integer_to_bytes(0x01) + self._private_key.raw() + index_bytes
                    ))
                else:
                    z_hmac: bytes = hmac_sha512(self._chain_code, (
                        integer_to_bytes(0x02) + self._public_key.raw_compressed()[1:] + index_bytes
                    ))
                    _hmac: bytes = hmac_sha512(self._chain_code, (
                        integer_to_bytes(0x03) + self._public_key.raw_compressed()[1:] + index_bytes
                    ))

                def new_private_key_left_part(zl: bytes, kl: bytes, ecc: IEllipticCurveCryptography) -> bytes:
                    zl: int = bytes_to_integer(zl[:28], endianness="little")
                    kl: int = bytes_to_integer(kl, endianness="little")

                    private_key_left: int = (zl * 8) + kl
                    if private_key_left % ecc.ORDER == 0:
                        raise Error("Computed child key is not valid, very unlucky index")

                    return integer_to_bytes(
                        private_key_left, bytes_num=(
                            KholawEd25519PrivateKey.length() // 2
                        ), endianness="little"
                    )

                def new_private_key_right_part(zr: bytes, kr: bytes) -> bytes:
                    zr: int = bytes_to_integer(zr, endianness="little")
                    kr: int = (zr + bytes_to_integer(kr, endianness="little")) % (2 ** 256)

                    return integer_to_bytes(
                        kr, bytes_num=(
                            KholawEd25519PrivateKey.length() // 2
                        ), endianness="little"
                    )

                z_hmacl, z_hmacr, _hmacl, _hmacr = (
                    z_hmac[:hmac_half_length], z_hmac[hmac_half_length:],
                    _hmac[:hmac_half_length], _hmac[hmac_half_length:]
                )

                kl_bytes, kr_bytes = (
                    new_private_key_left_part(
                        zl=z_hmacl, kl=self._private_key.raw()[:hmac_half_length], ecc=self._ecc
                    ), new_private_key_right_part(
                        zr=z_hmacr, kr=self._private_key.raw()[hmac_half_length:]
                    )
                )

                self._private_key, self._chain_code, self._parent_fingerprint = (
                    self._ecc.PRIVATE_KEY.from_bytes(
                        kl_bytes + kr_bytes
                    ),
                    _hmacr,
                    get_bytes(self.fingerprint())
                )
                self._public_key = self._private_key.public_key()
                self._depth, self._index, self._fingerprint = (
                    (self._depth + 1), index, get_bytes(self.fingerprint())
                )
            else:
                if index & 0x80000000:
                    raise DerivationError("Hardened derivation path is invalid for xpublic key")
                z_hmac: bytes = hmac_sha512(self._chain_code, (
                    integer_to_bytes(0x02) + self._public_key.raw_compressed()[1:] + index_bytes
                ))
                _hmac: bytes = hmac_sha512(self._chain_code, (
                    integer_to_bytes(0x03) + self._public_key.raw_compressed()[1:] + index_bytes
                ))

                def new_public_key_point(public_key: IPublicKey, zl: bytes, ecc: IEllipticCurveCryptography) -> IPoint:
                    zl: int = bytes_to_integer(zl[:28], endianness="little")
                    return public_key.point() + ((zl * 8) * ecc.GENERATOR)

                z_hmacl, z_hmacr, _hmacl, _hmacr = (
                    z_hmac[:hmac_half_length], z_hmac[hmac_half_length:],
                    _hmac[:hmac_half_length], _hmac[hmac_half_length:]
                )

                new_public_key_point: IPoint = new_public_key_point(
                    public_key=self._public_key, zl=z_hmacl, ecc=self._ecc
                )
                if new_public_key_point.x() == 0 and new_public_key_point.y() == 1:
                    raise Error("Computed public child key is not valid, very unlucky index")
                new_public_key: IPublicKey = self._ecc.PUBLIC_KEY.from_point(
                    new_public_key_point
                )
                self._parent_fingerprint = get_bytes(self.fingerprint())
                self._chain_code, self._public_key = (
                    _hmacr, new_public_key
                )
                self._depth, self._index, self._fingerprint = (
                    (self._depth + 1), index, get_bytes(self.fingerprint())
                )

            return self

        elif self._ecc.NAME in [
            "SLIP10-Ed25519", "SLIP10-Ed25519-Blake2b", "SLIP10-Ed25519-Monero"
        ]:
            if not self._private_key:
                raise DerivationError(
                    f"On {self._ecc.NAME} ECC, public key derivation is not supported"
                )

            index_bytes: bytes = struct.pack(">L", index)
            data_bytes: bytes = (
                integer_to_bytes(0x00) + self._private_key.raw() + index_bytes
            )

            _hmac: bytes = (
                hmac.digest(
                    self._chain_code, data_bytes, "sha512"
                ) if hasattr(hmac, "digest") else hmac.new(
                    self._chain_code, data_bytes, hashlib.sha512
                ).digest()
            )
            _hmacl, _hmacr = _hmac[:hmac_half_length], _hmac[hmac_half_length:]

            new_private_key: IPrivateKey = self._ecc.PRIVATE_KEY.from_bytes(_hmacl)

            self._parent_fingerprint = get_bytes(self.fingerprint())
            self._private_key, self._chain_code, self._public_key = (
                new_private_key, _hmacr, new_private_key.public_key()
            )
            self._depth, self._index, self._fingerprint = (
                (self._depth + 1), index, get_bytes(self.fingerprint())
            )

        elif self._ecc.NAME in [
            "SLIP10-Nist256p1", "SLIP10-Secp256k1"
        ]:
            index_bytes: bytes = struct.pack(">L", index)
            if not self._root_private_key and not self._root_public_key:
                raise DerivationError("You can't drive this master key")
            if not self._chain_code:
                raise DerivationError("You can't drive xprivate_key and private_key")

            if index & 0x80000000:
                if self._private_key is None:
                    raise DerivationError("Hardened derivation path is invalid for xpublic key")
                data_bytes: bytes = (
                    integer_to_bytes(0x00) + self._private_key.raw() + index_bytes
                )
            else:
                data_bytes: bytes = (
                    self._public_key.raw_compressed() + index_bytes
                )

            _hmac: bytes = (
                hmac.digest(
                    self._chain_code, data_bytes, "sha512"
                ) if hasattr(hmac, "digest") else hmac.new(
                    self._chain_code, data_bytes, hashlib.sha512
                ).digest()
            )
            _hmacl, _hmacr = _hmac[:hmac_half_length], _hmac[hmac_half_length:]

            _hmacl_int: int = bytes_to_integer(_hmacl)
            if _hmacl_int > self._ecc.ORDER:
                return None

            if self._private_key:
                private_key_int: int = bytes_to_integer(self._private_key.raw())
                key_int = (_hmacl_int + private_key_int) % self._ecc.ORDER
                if key_int == 0:
                    return None

                new_private_key: IPrivateKey = self._ecc.PRIVATE_KEY.from_bytes((
                    integer_to_bytes(0x00) * 32 + integer_to_bytes(key_int)
                )[-32:])

                self._parent_fingerprint = get_bytes(self.fingerprint())
                self._private_key, self._chain_code, self._public_key = (
                    new_private_key, _hmacr, new_private_key.public_key()
                )
                self._depth, self._index, self._fingerprint = (
                    (self._depth + 1), index, get_bytes(self.fingerprint())
                )
            else:
                new_public_key_point: IPoint = (
                    self._public_key.point() + (self._ecc.GENERATOR * bytes_to_integer(_hmacl))
                )
                new_public_key: IPublicKey = self._ecc.PUBLIC_KEY.from_point(
                    new_public_key_point
                )

                self._parent_fingerprint = get_bytes(self.fingerprint())
                self._chain_code, self._public_key = (
                    _hmacr, new_public_key
                )
                self._depth, self._index, self._fingerprint = (
                    (self._depth + 1), index, get_bytes(self.fingerprint())
                )
        return self

    def seed(self) -> Optional[str]:
        """
        Retrieves the seed value as a string if it exists.

        :return: The seed value as a string, or None if the seed is not set.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._seed) if self._seed else None

    def root_xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the root extended private key (xprv) in serialized format.

        :param version: The version bytes for the extended key. Defaults to Bitcoin mainnet P2PKH version.
        :type version: Union[bytes, int]
        :param encoded: Whether to return the key in encoded format. Defaults to True.
        :type encoded: bool

        :return: The root extended private key (xprv) in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

        if not self.root_private_key():
            return None

        return serialize(
            version=(
                integer_to_bytes(version) if isinstance(version, int) else get_bytes(version)
            ),
            depth=self._root_depth,
            parent_fingerprint=(integer_to_bytes(0x00) * 4),
            index=self._root_index,
            chain_code=self.root_chain_code(),
            key=("00" + self.root_private_key()),
            encoded=encoded
        ) if self.root_chain_code() else None

    def root_xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Generates the root extended public key (xpub) in serialized format.

        :param version: The version bytes for the extended key. Defaults to Bitcoin mainnet P2PKH version.
        :type version: Union[bytes, int]
        :param encoded: Whether to return the key in encoded format. Defaults to True.
        :type encoded: bool

        :return: The root extended public key (xpub) in serialized format, or None if the chain code is not set.
        :rtype: Optional[str]
        """

        return serialize(
            version=(
                integer_to_bytes(version) if isinstance(version, int) else get_bytes(version)
            ),
            depth=self._root_depth,
            parent_fingerprint=(integer_to_bytes(0x00) * 4),
            index=self._root_index,
            chain_code=self.root_chain_code(),
            key=self.root_public_key(
                public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
            ),
            encoded=encoded
        ) if self.root_chain_code() else None

    def root_private_key(self) -> Optional[str]:
        """
        Retrieves the root private key as a string.

        :return: The root private key as a hexadecimal string, or None if not set.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._root_private_key.raw()) if self._root_private_key else None

    def root_wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Retrieves the root private key in WIF format.

        :param wif_type: Optional. The type of WIF format to use ('WIF' or 'WIF_COMPRESSED').
                        If not specified, uses the default type stored in `_wif_type`.
        :type wif_type: Optional[str]

        :return: The root private key in WIF format as a string, or None if the root private key is not set.
        :rtype: Optional[str]
        """

        if self._wif_prefix is None:
            return None

        if wif_type:
            if wif_type not in WIF_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} WIF type", expected=WIF_TYPES.get_types(), got=wif_type
                )
            _wif_type: str = wif_type
        else:
            _wif_type: str = self._wif_type

        return private_key_to_wif(
            private_key=self.root_private_key(), wif_type=_wif_type, wif_prefix=self._wif_prefix
        ) if self.root_private_key() else None

    def root_chain_code(self) -> Optional[str]:
        """
        Retrieves the root chain code as a string.

        :return: The root chain code as a string, or None if the root chain code is not set.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._root_chain_code) if self._root_chain_code else None

    def root_public_key(self, public_key_type: Optional[str] = None) -> Optional[str]:
        """
        Retrieves the root public key as a string.

        :param public_key_type: The type of public key to retrieve. If None, defaults to the current object's public key type.
        :type public_key_type: Optional[str]

        :return: The root public key as a string, or None if the root public key is not set.
        :rtype: Optional[str]
        """

        if not self._root_public_key:
            return None

        if public_key_type:
            if public_key_type not in PUBLIC_KEY_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} public key type",
                    expected=PUBLIC_KEY_TYPES.get_types(),
                    got=public_key_type
                )
            _public_key_type: str = public_key_type
        else:
            _public_key_type: str = self._public_key_type

        if _public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            return bytes_to_string(self._root_public_key.raw_uncompressed())
        elif _public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            return bytes_to_string(self._root_public_key.raw_compressed())

    def xprivate_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
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

        if not self.private_key():
            return None

        return serialize(
            version=(
                integer_to_bytes(version) if isinstance(version, int) else get_bytes(version)
            ),
            depth=self._depth,
            parent_fingerprint=self.parent_fingerprint(),
            index=self._index,
            chain_code=self.chain_code(),
            key=("00" + self.private_key()),
            encoded=encoded
        ) if self.chain_code() else None

    def xpublic_key(
        self, version: Union[bytes, int] = Bitcoin.NETWORKS.MAINNET.XPUBLIC_KEY_VERSIONS.P2PKH, encoded: bool = True
    ) -> Optional[str]:
        """
        Retrieves the extended public key (xpublic key) as a serialized string.

        :param version: The version bytes or integer version of the xpublic key.
        :type version: Union[bytes, int]
        :param encoded: Flag indicating whether the key should be encoded.
        :type encoded: bool

        :return: The serialized xpublic key as a string, or None if the chain code is not set.
        :rtype: Optional[str]
        """

        return serialize(
            version=(
                integer_to_bytes(version) if isinstance(version, int) else get_bytes(version)
            ),
            depth=self._depth,
            parent_fingerprint=self.parent_fingerprint(),
            index=self._index,
            chain_code=self.chain_code(),
            key=self.public_key(
                public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
            ),
            encoded=encoded
        ) if self.chain_code() else None

    def private_key(self) -> Optional[str]:
        """
        Retrieves the private key as a string.

        :return: The private key as a string, or None if the private key is not set.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._private_key.raw()) if self._private_key else None

    def wif(self, wif_type: Optional[str] = None) -> Optional[str]:
        """
        Converts the private key to a WIF (Wallet Import Format) string.

        :param wif_type: Optional parameter specifying the type of WIF. If None, uses the instance's default type.
        :type wif_type: Optional[str]

        :return: The WIF representation of the private key, or None if the private key is not set.
        :rtype: Optional[str]
        """

        if self._wif_prefix is None:
            return None

        if wif_type:
            if wif_type not in WIF_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} WIF type",
                    expected=WIF_TYPES.get_types(),
                    got=wif_type
                )
            _wif_type: str = wif_type
        else:
            _wif_type: str = self._wif_type

        return private_key_to_wif(
            private_key=self.private_key(), wif_type=_wif_type, wif_prefix=self._wif_prefix
        ) if self.private_key() else None

    def wif_type(self) -> Optional[str]:
        """
        Retrieves the current WIF (Wallet Import Format) type used by the instance.

        :return: The current WIF type if a WIF is present, otherwise None.
        :rtype: Optional[str]
        """

        return self._wif_type if self.wif() else None

    def chain_code(self) -> Optional[str]:
        """
        Retrieves the chain code associated with the current instance.

        :return: The chain code as a string if available, otherwise None.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._chain_code) if self._chain_code else None

    def public_key(self, public_key_type: Optional[str] = None):
        """
        Retrieves the public key associated with the current instance.

        :param public_key_type: Optional. Specifies the type of public key to return.
                                If not provided, defaults to the type set during initialization.
        :type public_key_type: Optional[str]

        :return: The public key as a string based on the specified type.
        :rtype: str
        """

        if public_key_type:
            if public_key_type not in PUBLIC_KEY_TYPES.get_types():
                raise Error(
                    f"Invalid {self.name()} public key type",
                    expected=PUBLIC_KEY_TYPES.get_types(),
                    got=public_key_type
                )
            _public_key_type: str = public_key_type
        else:
            _public_key_type: str = self._public_key_type

        if _public_key_type == PUBLIC_KEY_TYPES.UNCOMPRESSED:
            return self.uncompressed()
        elif _public_key_type == PUBLIC_KEY_TYPES.COMPRESSED:
            return self.compressed()

    def public_key_type(self) -> str:
        """
        Retrieves the type of public key associated with the current instance.

        :return: The type of public key.
        :rtype: str
        """

        return self._public_key_type

    def compressed(self) -> str:
        """
        Retrieves the compressed form of the public key associated with the current instance.

        :return: The compressed public key.
        :rtype: str
        """

        return bytes_to_string(self._public_key.raw_compressed())

    def uncompressed(self) -> str:
        """
        Retrieves the uncompressed form of the public key associated with the current instance.

        :return: The uncompressed public key.
        :rtype: str
        """

        return bytes_to_string(self._public_key.raw_uncompressed())

    def hash(self) -> str:
        """
        Computes the hash of the public key using SHA-256 followed by RIPEMD-160.

        :return: The hash of the public key.
        :rtype: str
        """

        return bytes_to_string(ripemd160(sha256(get_bytes(self.public_key())).digest()))

    def fingerprint(self) -> str:
        """
        Computes the fingerprint of the BIP32HD object by hashing the public key
        and taking the first 4 bytes (8 characters) of the resulting hash.

        :return: The fingerprint of the BIP32HD object.
        :rtype: str
        """

        return self.hash()[:8]

    def parent_fingerprint(self) -> Optional[str]:
        """
        Retrieves the parent fingerprint of the BIP32HD object.

        :return: The parent fingerprint if available, otherwise None.
        :rtype: Optional[str]
        """

        return bytes_to_string(self._parent_fingerprint) if self._parent_fingerprint else None

    def depth(self) -> int:
        """
        Retrieves the depth of the BIP32HD object in the hierarchical tree.

        :return: The depth of the object.
        :rtype: int
        """

        return self._depth

    def path(self) -> str:
        """
        Retrieves the derivation path associated with the BIP32HD object.

        :return: The derivation path.
        :rtype: str
        """

        return self._derivation.path()

    def index(self) -> int:
        """
        Retrieves the index of the current BIP32HD object.

        :return: The index value.
        :rtype: int
        """

        return self._index

    def indexes(self) -> List[int]:
        """
        Retrieves the list of indexes from the derivation associated with this BIP32HD object.

        :return: The list of indexes.
        :rtype: List[int]
        """

        return self._derivation.indexes()

    def strict(self) -> Optional[bool]:
        """
        Retrieves the strict mode flag associated with this BIP32HD object.

        :return: The strict mode flag.
        :rtype: Optional[bool]
        """

        return self._strict

    def address(
        self,
        address: str = Bitcoin.ADDRESSES.P2PKH,
        public_key_address_prefix: int = Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX,
        script_address_prefix: int = Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
        hrp: str = Bitcoin.NETWORKS.MAINNET.HRP,
        witness_version: int = Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH,
        **kwargs
    ) -> str:
        """
        Generates an address based on the specified address type and parameters.

        :param address: The type of address to generate (e.g., P2PKH, P2SH, P2TR, P2WPKH, P2WPKHInP2SH, P2WSH, P2WSHInP2SH).
        :type address: str, optional
        :param public_key_address_prefix: Public key address prefix for encoding addresses, defaults to ``Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX``
        :type public_key_address_prefix: int, optional
        :param script_address_prefix: Script address prefix for encoding addresses, defaults to ``Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX``
        :type script_address_prefix: int, optional
        :param hrp: Human-readable part for Bech32 addresses, defaults to ``Bitcoin.NETWORKS.MAINNET.HRP``
        :type hrp: str, optional
        :param witness_version: Witness version for SegWit addresses, defaults to ``Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH``
        :type witness_version: int, optional
        :param kwargs: Additional keyword arguments for address generation.

        :return: The generated address.
        :rtype: str
        """

        if address == P2PKHAddress.name():
            return P2PKHAddress.encode(
                public_key=self._public_key,
                public_key_address_prefix=public_key_address_prefix,
                public_key_type=self._public_key_type
            )
        elif address == P2SHAddress.name():
            return P2SHAddress.encode(
                public_key=self._public_key,
                script_address_prefix=script_address_prefix,
                public_key_type=self._public_key_type
            )
        elif address == P2TRAddress.name():
            return P2TRAddress.encode(
                public_key=self._public_key,
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        elif address == P2WPKHAddress.name():
            return P2WPKHAddress.encode(
                public_key=self._public_key,
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        elif address == P2WPKHInP2SHAddress.name():
            return P2WPKHInP2SHAddress.encode(
                public_key=self._public_key,
                script_address_prefix=script_address_prefix,
                public_key_type=self._public_key_type
            )
        elif address == P2WSHAddress.name():
            return P2WSHAddress.encode(
                public_key=self._public_key,
                hrp=hrp,
                witness_version=witness_version,
                public_key_type=self._public_key_type
            )
        elif address == P2WSHInP2SHAddress.name():
            return P2WSHInP2SHAddress.encode(
                public_key=self._public_key,
                script_address_prefix=script_address_prefix,
                public_key_type=self._public_key_type
            )
        raise AddressError(
            f"Invalid {self.name()} address",
            expected=[
                P2PKHAddress.name(),
                P2SHAddress.name(),
                P2TRAddress.name(),
                P2WPKHAddress.name(),
                P2WPKHInP2SHAddress.name(),
                P2WSHAddress.name(),
                P2WSHInP2SHAddress.name()
            ],
            got=address
        )
