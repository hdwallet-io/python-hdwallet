#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Optional, Union
)

import unicodedata

from ...crypto import pbkdf2_hmac_sha512
from ...utils import bytes_to_string
from ...mnemonics import (
    IMnemonic, ElectrumV2Mnemonic, ELECTRUM_V2_MNEMONIC_TYPES
)
from ..iseed import ISeed


class ElectrumV2Seed(ISeed):
    """
    This class generates a root extended private key from a given seed using the
    Electrum-V2 standard. The Electrum-V2 standard defines a method for generating mnemonic
    phrases and converting them into a binary seed used for hierarchical
    deterministic wallets.

    .. note::
        This class inherits from the ``ISeed`` class, thereby ensuring that all functions are accessible.
    """

    seed_salt_modifier: str = "electrum"
    seed_pbkdf2_rounds: int = 2048

    lengths: List[int] = [128]

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the seeds class.

        :return: The name of the seeds class.
        :rtype: str
        """

        return "Electrum-V2"

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: Union[str, IMnemonic],
        passphrase: Optional[str] = None,
        language: Optional[str] = None,
        mnemonic_type=ELECTRUM_V2_MNEMONIC_TYPES.STANDARD
    ) -> str:
        """
        Converts an Electrum V2 mnemonic phrase to its corresponding seed.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]
        :param passphrase: An optional passphrase to strengthen the security of the seed. Defaults to None.
        :type passphrase: Optional[str]
        :param mnemonic_type: The type of Electrum V2 mnemonic, defaults to STANDARD.
        :type mnemonic_type: str

        :return: The derived seed as a string.
        :rtype: str
        """
        if not isinstance(mnemonic, IMnemonic):
            mnemonic = ElectrumV2Mnemonic(mnemonic=mnemonic, language=language)
        assert isinstance(mnemonic, ElectrumV2Mnemonic)

        salt: str = unicodedata.normalize("NFKD", (
            (cls.seed_salt_modifier + passphrase) if passphrase else cls.seed_salt_modifier
        ))
        return bytes_to_string(pbkdf2_hmac_sha512(
            password=unicodedata.normalize("NFKD", mnemonic.mnemonic()), salt=salt, iteration_num=cls.seed_pbkdf2_rounds
        ))
