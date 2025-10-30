#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Dict, List, Type, Union
)

from ..exceptions import (
    ECCError, PublicKeyError
)
from ..utils import get_bytes
from .kholaw import (  # noqa: F401
    KholawEd25519ECC, KholawEd25519Point, KholawEd25519PublicKey, KholawEd25519PrivateKey
)
from .slip10 import (  # noqa: F401
    SLIP10Ed25519ECC, SLIP10Ed25519Point, SLIP10Ed25519PublicKey, SLIP10Ed25519PrivateKey,
    SLIP10Ed25519Blake2bECC, SLIP10Ed25519Blake2bPoint, SLIP10Ed25519Blake2bPublicKey, SLIP10Ed25519Blake2bPrivateKey,
    SLIP10Ed25519MoneroECC, SLIP10Ed25519MoneroPoint, SLIP10Ed25519MoneroPublicKey, SLIP10Ed25519MoneroPrivateKey,
    SLIP10Nist256p1ECC, SLIP10Nist256p1Point, SLIP10Nist256p1PublicKey, SLIP10Nist256p1PrivateKey,
    SLIP10Secp256k1ECC, SLIP10Secp256k1Point, SLIP10Secp256k1PublicKey, SLIP10Secp256k1PrivateKey
)
from .iecc import (  # noqa: F401
    IPoint, IPublicKey, IPrivateKey, IEllipticCurveCryptography
)


class ECCS:
    """
    A class that manages a dictionary of ecc classes.

    This class provides methods to retrieve names and classes of various entropy implementations,
    as well as methods to validate and access specific ecc classes by name.

    Here are available ecc names and classes:

    +--------------------------+--------------------------------------------------------------------------+
    | Name                     | Class                                                                    |
    +==========================+==========================================================================+
    | KholawEd25519ECC         | :class:`hdwallet.eccs.kholaw.ed25519.KholawEd25519ECC`                   |
    +--------------------------+--------------------------------------------------------------------------+
    | SLIP10Ed25519ECC         | :class:`hdwallet.eccs.slip10.ed25519.SLIP10Ed25519ECC`                   |
    +--------------------------+--------------------------------------------------------------------------+
    | SLIP10Ed25519Blake2bECC  | :class:`hdwallet.eccs.slip10.ed25519.blake2b.SLIP10Ed25519Blake2bECC`    |
    +--------------------------+--------------------------------------------------------------------------+
    | SLIP10Ed25519MoneroECC   | :class:`hdwallet.eccs.slip10.ed25519.monero.SLIP10Ed25519MoneroECC`      |
    +--------------------------+--------------------------------------------------------------------------+
    | SLIP10Nist256p1ECC       | :class:`hdwallet.eccs.slip10.nist256p1.SLIP10Nist256p1ECC`               |
    +--------------------------+--------------------------------------------------------------------------+
    | SLIP10Secp256k1ECC       | :class:`hdwallet.eccs.slip10.secp256k1.SLIP10Secp256k1ECC`               |
    +--------------------------+--------------------------------------------------------------------------+
    """

    dictionary: Dict[str, Type[IEllipticCurveCryptography]] = {
        KholawEd25519ECC.NAME: KholawEd25519ECC,
        SLIP10Ed25519ECC.NAME: SLIP10Ed25519ECC,
        SLIP10Ed25519Blake2bECC.NAME: SLIP10Ed25519Blake2bECC,
        SLIP10Ed25519MoneroECC.NAME: SLIP10Ed25519MoneroECC,
        SLIP10Nist256p1ECC.NAME: SLIP10Nist256p1ECC,
        SLIP10Secp256k1ECC.NAME: SLIP10Secp256k1ECC
    }

    @classmethod
    def names(cls) -> List[str]:
        """
        Get the names from the class's dictionary.

        :return: A list of names stored as keys in the `dictionary`.
        :rtype: List[str]
        """

        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[IEllipticCurveCryptography]]:
        """
        Get the list of elliptic curve cryptography (ECC) classes from the class's dictionary.

        :return: A list of ECC classes stored as values in the `dictionary`.
        :rtype: List[Type[IEllipticCurveCryptography]]
        """

        return list(cls.dictionary.values())

    @classmethod
    def ecc(cls, name: str) -> Type[IEllipticCurveCryptography]:
        """
        Retrieve an elliptic curve cryptography (ECC) class by name.

        :param name: The name of the ECC class to retrieve.
        :type name: str

        :return: The ECC class corresponding to the given name.
        :rtype: Type[IEllipticCurveCryptography]
        """

        if not cls.is_ecc(name=name):
            raise ECCError(
                "Invalid ECC name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_ecc(cls, name: str) -> bool:
        """
        Check if the given name is a valid ECC class name.

        :param name: The name to check.
        :type name: str

        :return: True if the name is a valid ECC class name, False otherwise.
        :rtype: bool
        """

        return name in cls.names()


def validate_and_get_public_key(
    public_key: Union[bytes, str, IPublicKey], public_key_cls: Type[IPublicKey]
) -> IPublicKey:
    """
    Validate and convert the input to an IPublicKey instance.

    :param public_key: The public key to validate and convert. It can be of type bytes, str, or IPublicKey.
    :type public_key: Union[bytes, str, IPublicKey]
    :param public_key_cls: The class to use for creating an IPublicKey instance from bytes.
    :type public_key_cls: Type[IPublicKey]

    :return: A valid IPublicKey instance.
    :rtype: IPublicKey
    """

    try:
        if isinstance(public_key, bytes):
            public_key: IPublicKey = public_key_cls.from_bytes(public_key)
        elif isinstance(public_key, str):
            public_key: IPublicKey = public_key_cls.from_bytes(get_bytes(public_key))
        elif not isinstance(public_key, public_key_cls):
            ecc: Type[IEllipticCurveCryptography] = ECCS.ecc(
                name=public_key_cls.name()
            )
            raise PublicKeyError(
                f"Invalid {ecc.NAME} public key instance", expected=public_key_cls, got=type(public_key)
            )
        return public_key
    except ValueError as error:
        raise PublicKeyError("Invalid public key data") from error


__all__: List[str] = [
    "IPoint", "IPublicKey", "IPrivateKey", "IEllipticCurveCryptography",
    "KholawEd25519Point", "KholawEd25519PublicKey", "KholawEd25519PrivateKey",
    "SLIP10Ed25519Point", "SLIP10Ed25519PublicKey", "SLIP10Ed25519PrivateKey",
    "SLIP10Ed25519Blake2bPoint", "SLIP10Ed25519Blake2bPublicKey", "SLIP10Ed25519Blake2bPrivateKey",
    "SLIP10Ed25519MoneroPoint", "SLIP10Ed25519MoneroPublicKey", "SLIP10Ed25519MoneroPrivateKey",
    "SLIP10Nist256p1Point", "SLIP10Nist256p1PublicKey", "SLIP10Nist256p1PrivateKey",
    "SLIP10Secp256k1Point", "SLIP10Secp256k1PublicKey", "SLIP10Secp256k1PrivateKey",
    "ECCS", "validate_and_get_public_key"
] + [
    cls.__name__ for cls in ECCS.classes()
]
