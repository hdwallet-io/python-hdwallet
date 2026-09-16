#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union
)

import unicodedata

from ..crypto import pbkdf2_hmac_sha512
from ..exceptions import MnemonicError
from ..utils import bytes_to_string
from ..mnemonics import (
    IMnemonic, BIP39Mnemonic
)
from .iseed import ISeed


class BIP39Seed(ISeed):
    """
    This class generates a root extended private key from a given seed using the
    BIP39 standard. The BIP39 standard defines a method for generating mnemonic
    phrases and converting them into a binary seed used for hierarchical
    deterministic wallets.

    .. note::
        This class inherits from the ``ISeed`` class, thereby ensuring that all functions are accessible.
    """

    seed_salt_modifier: str = "mnemonic"
    seed_pbkdf2_rounds: int = 2048

    length = 128

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the seeds class.

        :return: The name of the seeds class.
        :rtype: str
        """

        return "BIP39"

    @classmethod
    def from_mnemonic(cls, mnemonic: Union[str, IMnemonic], passphrase: Optional[str] = None) -> str:
        """
        Converts a mnemonic phrase to its corresponding seed.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :param passphrase: An optional passphrase used for additional security when decoding the mnemonic phrase.
        :type passphrase: Optional[str]

        :return: The decoded seed as a string.
        :rtype: str
        """

        mnemonic = (
            mnemonic.mnemonic() if isinstance(mnemonic, IMnemonic) else mnemonic
        )
        if not BIP39Mnemonic.is_valid(mnemonic=mnemonic):
            raise MnemonicError(f"Invalid {cls.name()} mnemonic words")

        salt: str = unicodedata.normalize("NFKD", (
            (cls.seed_salt_modifier + passphrase) if passphrase else cls.seed_salt_modifier
        ))
        return bytes_to_string(pbkdf2_hmac_sha512(
            password=mnemonic, salt=salt, iteration_num=cls.seed_pbkdf2_rounds
        ))
