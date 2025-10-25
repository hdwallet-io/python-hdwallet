#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union
)

import hashlib
import cbor2

from ..eccs import (
    IEllipticCurveCryptography, IPoint, IPublicKey, KholawEd25519ECC, KholawEd25519PrivateKey
)
from ..seeds import ISeed
from ..crypto import (
    pbkdf2_hmac_sha512, hmac_sha512, hmac_sha256, sha512
)
from ..cryptocurrencies import Cardano
from ..exceptions import (
    Error, AddressError, DerivationError, PublicKeyError, PrivateKeyError, SeedError
)
from ..utils import (
    get_bytes,
    get_hmac,
    reset_bits,
    set_bits,
    add_no_carry,
    multiply_scalar_no_carry,
    bytes_to_string,
    are_bits_set,
    integer_to_bytes,
    bytes_to_integer
)
from ..addresses.cardano import CardanoAddress
from .bip32 import BIP32HD


class CardanoHD(BIP32HD):

    _cardano_type: str

    def __init__(self, cardano_type: str) -> None:
        """
        Initialize a CardanoHD instance with the specified Cardano type.

        :param cardano_type: Type of Cardano instance to create.
        :type cardano_type: str
        """

        super(CardanoHD, self).__init__(
            ecc=KholawEd25519ECC
        )
        if cardano_type not in Cardano.TYPES.get_cardano_types():
            raise Error(
                "Invalid Cardano type", expected=Cardano.TYPES.get_cardano_types(), got=cardano_type
            )
        self._cardano_type = cardano_type

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the cardano class.

        :return: The name of the cardano class.
        :rtype: str
        """
        return "Cardano"

    def from_seed(self, seed: Union[str, ISeed], passphrase: Optional[str] = None) -> "CardanoHD":
        """
        Derive hierarchical deterministic keys from a seed for the specified Cardano type.

        :param seed: Seed to derive keys from. Can be either a string or an instance of ISeed.
        :type seed: Union[str, ISeed]
        :param passphrase: Optional passphrase for key derivation (default is None).
        :type passphrase: Optional[str]

        :return: This CardanoHD instance with derived keys set.
        :rtype: CardanoHD
        """

        try:
            self._seed = get_bytes(
                seed.seed() if isinstance(seed, ISeed) else seed
            )
        except ValueError as error:
            raise SeedError("Invalid seed data") from error

        if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
            if len(self._seed) != 32:
                raise Error("Invalid seed length", expected=32, got=len(self._seed))

            def tweak_master_key_bits(data: bytes) -> bytes:
                data: bytearray = bytearray(data)
                # Clear the lowest 3 bits of the first byte of kL
                data[0] = reset_bits(data[0], 0x07)
                # Clear the highest bit of the last byte of kL
                data[31] = reset_bits(data[31], 0x80)
                # Set the second-highest bit of the last byte of kL
                data[31] = set_bits(data[31], 0x40)
                return bytes(data)

            data: bytes = cbor2.dumps(self._seed)
            iteration_number: int = 1

            success: bool = True
            while success:

                i: bytes = hmac_sha512(
                    data, b"Root Seed Chain %d" % iteration_number
                )
                il: bytes = i[:hashlib.sha512().digest_size // 2]
                ir: bytes = i[hashlib.sha512().digest_size // 2:]
                il: bytes = tweak_master_key_bits(sha512(il))

                success = are_bits_set(il[31], 0x20)
                if success:
                    iteration_number += 1

                self._root_private_key = self._ecc.PRIVATE_KEY.from_bytes(il)
                self._root_chain_code = ir

        elif self._cardano_type in [
            Cardano.TYPES.BYRON_ICARUS, Cardano.TYPES.SHELLEY_ICARUS
        ]:
            if len(self._seed) < 16:
                raise Error("Invalid seed length", expected="< 16", got=len(self._seed))

            pbkdf2_passphrase, pbkdf2_rounds, pbkdf2_output_length = (
                (passphrase if passphrase else ""), 4096, 96
            )

            def tweak_master_key_bits(data: bytes) -> bytes:

                data: bytearray = bytearray(data)
                # Clear the lowest 3 bits of the first byte of kL
                data[0] = reset_bits(data[0], 0x07)
                # Clear the highest 3 bits of the last byte of kL (standard kholaw only clears the highest one)
                data[31] = reset_bits(data[31], 0xE0)
                # Set the second-highest bit of the last byte of kL
                data[31] = set_bits(data[31], 0x40)

                return bytes(data)

            key: bytes = tweak_master_key_bits(pbkdf2_hmac_sha512(
                pbkdf2_passphrase, self._seed, pbkdf2_rounds, pbkdf2_output_length
            ))

            self._root_private_key, self._root_chain_code = (
                self._ecc.PRIVATE_KEY.from_bytes(
                    key[:KholawEd25519PrivateKey.length()]
                ), key[KholawEd25519PrivateKey.length():]
            )

        elif self._cardano_type in [
            Cardano.TYPES.BYRON_LEDGER, Cardano.TYPES.SHELLEY_LEDGER
        ]:
            if len(self._seed) < 16:
                raise Error("Invalid seed length", expected="< 16", got=len(self._seed))

            hmac_half_length: int = hashlib.sha512().digest_size // 2

            # Compute HMAC, retry if the resulting private key is not valid
            self._hmac: bytes = b""
            hmac_data: bytes = self._seed
            success: bool = False

            while not success:
                self._hmac = hmac_sha512(
                    get_hmac(ecc_name=self._ecc.NAME), hmac_data
                )
                # Compute kL and kR
                success = ((self._hmac[:hmac_half_length][31] & 0x20) == 0)
                if not success:
                    hmac_data = self._hmac

            def tweak_master_key_bits(data: bytes) -> bytes:

                data: bytearray = bytearray(data)
                # Clear the lowest 3 bits of the first byte of kL
                data[0] = reset_bits(data[0], 0x07)
                # Clear the highest bit of the last byte of kL
                data[31] = reset_bits(data[31], 0x80)
                # Set the second-highest bit of the last byte of kL
                data[31] = set_bits(data[31], 0x40)

                return bytes(data)

            # Compute kL and kR
            kl: bytes = self._hmac[:hmac_half_length]
            kr: bytes = self._hmac[hmac_half_length:]
            # Tweak kL bytes
            kl: bytes = tweak_master_key_bits(kl)
            chain_code: bytes = hmac_sha256(
                get_hmac(ecc_name=self._ecc.NAME), b"\x01" + self._seed
            )
            self._root_private_key, self._root_chain_code = (
                self._ecc.PRIVATE_KEY.from_bytes(
                    (kl + kr)
                ), chain_code
            )

        self._root_public_key = self._root_private_key.public_key()
        self._private_key, self._chain_code, self._parent_fingerprint = (
            self._root_private_key, self._root_chain_code, b"\x00\x00\x00\x00"
        )
        self._public_key = self._private_key.public_key()
        self._strict = True
        return self

    def from_private_key(self, private_key: str) -> "CardanoHD":
        """
        Initialize this CardanoHD instance from a given private key.

        :param private_key: The private key to initialize from.
        :type private_key: str

        :return: This CardanoHD instance initialized with the provided private key.
        :rtype: CardanoHD
        """

        try:
            if self._cardano_type in [
                Cardano.TYPES.BYRON_ICARUS, Cardano.TYPES.BYRON_LEGACY, Cardano.TYPES.BYRON_LEDGER
            ]:
                raise Error(f"From private key is not implemented for Cardano {self._cardano_type} type")
            self._private_key = self._ecc.PRIVATE_KEY.from_bytes(get_bytes(private_key))
            self._public_key = self._private_key.public_key()
            self._strict = None
            return self
        except ValueError as error:
            raise PrivateKeyError("Invalid private key data") from error

    def from_public_key(self, public_key: str) -> "CardanoHD":
        """
        Initialize this CardanoHD instance from a given public key.

        :param public_key: The public key to initialize from.
        :type public_key: str

        :return: This CardanoHD instance initialized with the provided public key.
        :rtype: CardanoHD
        """

        try:
            if self._cardano_type in [
                Cardano.TYPES.BYRON_ICARUS, Cardano.TYPES.BYRON_LEGACY, Cardano.TYPES.BYRON_LEDGER
            ]:
                raise Error(f"From public key is not implemented for Cardano {self._cardano_type} type")
            self._public_key = self._ecc.PUBLIC_KEY.from_bytes(get_bytes(public_key))
            self._strict = None
            return self
        except ValueError as error:
            raise PublicKeyError("Invalid public key data") from error

    def drive(self, index: int) -> Optional["CardanoHD"]:
        """
        Derives a new CardanoHD instance at the specified index.

        :param index: The index of the child HD wallet to derive.
        :type index: int

        :return: A new CardanoHD instance derived at the specified index.
        :rtype: CardanoHD or None
        """

        hmac_half_length: int = hashlib.sha512().digest_size // 2

        if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
            index_bytes: bytes = integer_to_bytes(
                data=index, bytes_num=4, endianness="big"
            )
        else:
            index_bytes: bytes = integer_to_bytes(
                data=index, bytes_num=4, endianness="little"
            )

        if self._private_key:
            if index & 0x80000000:
                if self._private_key is None:
                    raise DerivationError("Hardened derivation path is invalid for xpublic key")
                z_hmac: bytes = hmac_sha512(self._chain_code, (
                    b"\x00" + self._private_key.raw() + index_bytes
                ))
                _hmac: bytes = hmac_sha512(self._chain_code, (
                    b"\x01" + self._private_key.raw() + index_bytes
                ))
            else:
                z_hmac: bytes = hmac_sha512(self._chain_code, (
                    b"\x02" + self._public_key.raw_compressed()[1:] + index_bytes
                ))
                _hmac: bytes = hmac_sha512(self._chain_code, (
                    b"\x03" + self._public_key.raw_compressed()[1:] + index_bytes
                ))

            def new_private_key_left_part(zl: bytes, kl: bytes, ecc: IEllipticCurveCryptography) -> bytes:
                if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
                    zl: int = bytes_to_integer(
                        multiply_scalar_no_carry(zl, 8), endianness="little"
                    )
                    kl: int = bytes_to_integer(kl, endianness="little")

                    return integer_to_bytes(
                        (zl + kl) % ecc.ORDER, bytes_num=32, endianness="little"
                    )
                else:
                    zl: int = bytes_to_integer(zl[:28], endianness="little")
                    kl: int = bytes_to_integer(kl, endianness="little")

                    private_key_left: int = (zl * 8) + kl
                    # Discard child if multiple of curve order
                    if private_key_left % ecc.ORDER == 0:
                        raise Error("Computed child key is not valid, very unlucky index")

                    return integer_to_bytes(
                        private_key_left, bytes_num=(
                            KholawEd25519PrivateKey.length() // 2
                        ), endianness="little"
                    )

            def new_private_key_right_part(zr: bytes, kr: bytes) -> bytes:
                if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
                    return add_no_carry(zr, kr)
                else:
                    zr: int = bytes_to_integer(zr, endianness="little")
                    kr: int = (zr + bytes_to_integer(kr, endianness="little")) % (2 ** 256)

                    return integer_to_bytes(
                        kr, bytes_num=(
                            KholawEd25519PrivateKey.length() // 2
                        ), endianness="little"
                    )

            z_hmacl, z_hmacr, _hmacl, _hmacr = (  # noqa: F841
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
                b"\x02" + self._public_key.raw_compressed()[1:] + index_bytes
            ))
            _hmac: bytes = hmac_sha512(self._chain_code, (
                b"\x03" + self._public_key.raw_compressed()[1:] + index_bytes
            ))

            def new_public_key_point(public_key: IPublicKey, zl: bytes, ecc: IEllipticCurveCryptography) -> IPoint:
                if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
                    zl: int = bytes_to_integer(multiply_scalar_no_carry(zl, 8), endianness="little")
                    return public_key.point() + (zl * ecc.GENERATOR)
                else:
                    zl: int = bytes_to_integer(zl[:28], endianness="little")
                    return public_key.point() + ((zl * 8) * ecc.GENERATOR)

            z_hmacl, z_hmacr, _hmacl, _hmacr = (  # noqa: F841
                z_hmac[:hmac_half_length], z_hmac[hmac_half_length:],
                _hmac[:hmac_half_length], _hmac[hmac_half_length:]
            )
            new_public_key_point: IPoint = new_public_key_point(
                public_key=self._public_key, zl=z_hmacl, ecc=self._ecc
            )
            # If the public key is the identity point (0, 1) discard the child
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

    def root_xprivate_key(
        self, version: Union[bytes, int] = Cardano.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
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
        return super(CardanoHD, self).root_xprivate_key(version=version, encoded=encoded)

    def xprivate_key(
        self, version: Union[bytes, int] = Cardano.NETWORKS.MAINNET.XPRIVATE_KEY_VERSIONS.P2PKH, encoded: bool = True
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
        return super(CardanoHD, self).xprivate_key(version=version, encoded=encoded)

    def path_key(self) -> Optional[str]:
        """
        Derives a path key based on the current CardanoHD instance.

        :return: The derived path key as a hexadecimal string.
        :rtype: str or None
        """

        if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
            self._root_public_key = self._root_private_key.public_key()
            return bytes_to_string(pbkdf2_hmac_sha512(
                (self._root_public_key.raw_compressed()[1:] + self._root_chain_code), "address-hashing", 500, 32
            ))
        return None

    def address(self, **kwargs) -> str:
        """
        Generates an address based on the current CardanoHD instance and specified parameters.

        :param kwargs: Additional parameters based on Cardano type and address type.

        :return: Generated Cardano address as a string.
        :rtype: str
        """

        if self._cardano_type == Cardano.TYPES.BYRON_LEGACY:
            return CardanoAddress.encode_byron_legacy(
                public_key=self._public_key,
                path=self.path(),
                path_key=self.path_key(),
                chain_code=self._chain_code,
                address_type=kwargs.get(
                    "address_type", Cardano.ADDRESS_TYPES.PUBLIC_KEY
                )
            )
        elif self._cardano_type in [
            Cardano.TYPES.BYRON_ICARUS, Cardano.TYPES.BYRON_LEDGER
        ]:
            return CardanoAddress.encode_byron_icarus(
                public_key=self._public_key,
                chain_code=self._chain_code,
                address_type=kwargs.get(
                    "address_type", Cardano.ADDRESS_TYPES.PUBLIC_KEY
                )
            )
        elif self._cardano_type in [
            Cardano.TYPES.SHELLEY_ICARUS, Cardano.TYPES.SHELLEY_LEDGER
        ]:
            if kwargs.get("address_type") == Cardano.ADDRESS_TYPES.PAYMENT:
                if not kwargs.get("staking_public_key"):
                    raise ValueError("staking_public_key param is required for payment address type")
                return CardanoAddress.encode_shelley(
                    public_key=self._public_key,
                    staking_public_key=kwargs.get("staking_public_key"),
                    network=kwargs.get("network", "mainnet")
                )
            elif kwargs.get("address_type") in [
                Cardano.ADDRESS_TYPES.STAKING, Cardano.ADDRESS_TYPES.REWARD
            ]:
                return CardanoAddress.encode_shelley_staking(
                    public_key=self._public_key,
                    network=kwargs.get("network", "mainnet")
                )
            raise AddressError(
                f"Invalid Cardano {self._cardano_type} address type", expected=[
                    Cardano.ADDRESS_TYPES.PAYMENT, Cardano.ADDRESS_TYPES.STAKING, Cardano.ADDRESS_TYPES.REWARD
                ], got=kwargs.get("address_type")
            )
