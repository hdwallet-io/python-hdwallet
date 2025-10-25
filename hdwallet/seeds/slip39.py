#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union
)

from ..exceptions import EntropyError
from ..mnemonics import IMnemonic
from ..mnemonics.bip39 import BIP39Mnemonic
from ..mnemonics.slip39 import SLIP39Mnemonic
from .iseed import ISeed


class SLIP39Seed(ISeed):
    """This class transmits a seed collected from SLIP-39 recovery.  This entropy is used /directly/
    to produce hierarchical deterministic wallets, unlike for BIP39 where the original entropy is
    hashed and extended to 512 bits before being used.  The 3 valid seed sizes are 128, 256 and 512
    bits.

    Once recovered from SLIP-39 encoding, the seed data is provided and presented as simple hex.

    .. note::
        This class inherits from the ``ISeed`` class, thereby ensuring that all functions are accessible.

    """
    @classmethod
    def name(cls) -> str:
        """
        Get the name of the seeds class.

        :return: The name of the seeds class.
        :rtype: str
        """

        return "SLIP39"

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: Union[str, IMnemonic],
        passphrase: Optional[str] = None,
        language: Optional[str] = None,
    ) -> str:
        """Converts a mnemonic phrase to its corresponding raw entropy.

        The Mnemonic representation for SLIP-39 seeds is simple hex, and must be of the supported
        SLIP-39 entropy sizes: 128, 256 or 512 bits.

        To support the backup and recovery of BIP-39 mnemonic phrases to/from SLIP-39, we accept a
        BIP39 IMnemonic or mnemonic phrase, and recover the underlying (original) entropy encoded by
        the BIP-39 mnemonic phrase.

        In other words, you may supply a 12-word BIP39 Mnemonic like "zoo zoo ... zoo wrong", and
        recover the original seed entropy 0xffff...ff.  For SLIP-39 HD wallet derivations, this seed
        entropy is used /directly/ to derive the wallets, unlike for BIP-39 which hashes the entropy
        to extend it to 512 bits and uses the extended entropy to derive the wallets.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :param passphrase: An optional passphrase used for additional security when decoding the mnemonic phrase.
        :type passphrase: Optional[str]

        :return: The decoded seed as a string.
        :rtype: str

        """

        if not isinstance(mnemonic, IMnemonic):
            # Not an IMnemonic; must be a str.  Try the supported mnemonic encodings we'll allow for
            # SLIP39 seeds, converting the mnemonic phrase to an IMnemonic if recognized.
            #
            # TODO: Add other Seed entropy Mnemonics
            allowed_entropy = [
                SLIP39Mnemonic,
                BIP39Mnemonic,
            ]

            for M in allowed_entropy:
                if M.is_valid(mnemonic, language=language):
                    mnemonic = M(mnemonic=mnemonic, language=language)
                    break
            else:
                raise EntropyError(
                    "Invalid entropy instance", expected=[str, ] + allowed_entropy, got=type(mnemonic),
                )

        # Some kind of IMnemonic (eg. a BIP39Mnemonic); get and return its raw entropy as hex
        entropy = mnemonic.decode(mnemonic=mnemonic.mnemonic(), language=mnemonic.language())
        if len(entropy) * 4 not in SLIP39Mnemonic.words_to_entropy_strength.values():
            raise EntropyError(
                "Invalid entropy size in bits", expected=SLIP39Mnemonic.words_to_entropy_strength.values(), got=len(entropy) * 4,
            )
        return entropy
