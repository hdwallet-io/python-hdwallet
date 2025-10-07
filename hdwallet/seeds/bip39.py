#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union
)

import unicodedata

from ..crypto import pbkdf2_hmac_sha512
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

    The supplied passphrase is always used in extending the original entropy
    (encoded in the BIP-39 mnemonic phrase) into the 512-bit seed used to derive
    HD wallets.

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
    def from_mnemonic(
        cls,
        mnemonic: Union[str, IMnemonic],
        passphrase: Optional[str] = None,
        language: Optional[str] = None
    ) -> str:
        """Converts a canonical mnemonic phrase to its corresponding seed.  Since a mnemonic string
        may contain abbreviations, we canonicalize it by round-tripping it through the appropriate
        IMnemonic type; this raises a MnemonicError exception for invalid mnemonics or languages.

        BIP39 stretches a prefix + (passphrase or "") + normalized mnemonic to produce the 512-bit seed.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :param passphrase: An optional passphrase used for additional security when decoding the mnemonic phrase.
        :type passphrase: Optional[str]

        :return: The decoded seed as a string.
        :rtype: str

        """
        if not isinstance(mnemonic, IMnemonic):
            mnemonic = BIP39Mnemonic(mnemonic=mnemonic, language=language)
        assert isinstance(mnemonic, IMnemonic)

        # Normalize mnemonic to NFKD for seed generation as required by BIP-39 specification
        normalized_mnemonic: str = unicodedata.normalize("NFKD", mnemonic.mnemonic())

        # Salt normalization should use NFKD as per BIP-39 specification
        salt: str = unicodedata.normalize("NFKD", (
            (cls.seed_salt_modifier + passphrase) if passphrase else cls.seed_salt_modifier
        ))
        return bytes_to_string(pbkdf2_hmac_sha512(
            password=normalized_mnemonic, salt=salt, iteration_num=cls.seed_pbkdf2_rounds
        ))
