#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import Union

from ...crypto import sha256
from ...exceptions import MnemonicError
from ...mnemonics import (
    IMnemonic, ElectrumV1Mnemonic
)
from ...utils import bytes_to_string, encode
from ..iseed import ISeed


class ElectrumV1Seed(ISeed):
    """
    This class generates a root extended private key from a given seed using the
    Electrum-V1 standard. The Electrum-V1 standard defines a method for generating mnemonic
    phrases and converting them into a binary seed used for hierarchical
    deterministic wallets.

    .. note::
        This class inherits from the ``ISeed`` class, thereby ensuring that all functions are accessible.
    """

    hash_iteration_number: int = 10 ** 5

    length = 64

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the seeds class.

        :return: The name of the seeds class.
        :rtype: str
        """

        return "Electrum-V1"

    @classmethod
    def from_mnemonic(cls, mnemonic: Union[str, IMnemonic], **kwargs) -> str:
        """
        Converts an Electrum V1 mnemonic phrase to its corresponding hashed entropy.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :return: The hashed entropy as a string.
        :rtype: str
        """

        mnemonic = (
            mnemonic.mnemonic() if isinstance(mnemonic, IMnemonic) else mnemonic
        )
        if not ElectrumV1Mnemonic.is_valid(mnemonic=mnemonic):
            raise MnemonicError(f"Invalid {cls.name()} mnemonic words")

        entropy: str = ElectrumV1Mnemonic.decode(mnemonic)
        entropy_hash: bytes = encode(entropy)
        for _ in range(cls.hash_iteration_number):
            entropy_hash = sha256(entropy_hash + encode(entropy))

        return bytes_to_string(entropy_hash)
