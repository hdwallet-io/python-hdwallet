#!/usr/bin/env python3

# Copyright © 2020-2025 , Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Union, List
)

import cbor2
import re

from ..mnemonics import (
    IMnemonic, BIP39Mnemonic
)
from ..cryptocurrencies import Cardano
from ..crypto import blake2b_256
from ..exceptions import (
    Error, SeedError
)
from ..utils import (
    get_bytes, bytes_to_string
)
from . import (
    ISeed, BIP39Seed
)


class CardanoSeed(ISeed):
    """
    This class generates a root extended private key from a given seed using the
    cardano standard. The cardano standard defines a method for generating mnemonic
    phrases and converting them into a binary seed used for hierarchical
    deterministic wallets.

    .. note::
        This class inherits from the ``ISeed`` class, thereby ensuring that all functions are accessible.
    """

    _cardano_type: str
    lengths: List[int] = [
        32,  # Byron-Icarus and Shelly-Icarus
        128,  # Byron-Ledger and Shelly-Ledger
        64  # Byron-Legacy
    ]

    def __init__(
        self, seed: str, cardano_type: str = Cardano.TYPES.BYRON_ICARUS, passphrase: Optional[str] = None
    ) -> None:
        """
        Initialize a CardanoSeed object.

        :param seed: The seed value used to generate Cardano keys.
        :type seed: str
        :param cardano_type: The type of Cardano seed. Defaults to Cardano.TYPES.BYRON_ICARUS.
        :type cardano_type: str, optional

        :param passphrase: Optional passphrase for deriving the seed. Defaults to None.
        :type passphrase: str, optional
        """

        super(CardanoSeed, self).__init__(
            seed=seed, cardano_type=cardano_type, passphrase=passphrase
        )

        if cardano_type not in Cardano.TYPES.get_cardano_types():
            raise SeedError(
                "Invalid Cardano type", expected=Cardano.TYPES.get_cardano_types(), got=cardano_type
            )

        self._cardano_type = cardano_type
        self._seed = seed

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the seeds class.

        :return: The name of the seeds class.
        :rtype: str
        """

        return "Cardano"

    def cardano_type(self) -> str:
        """
        Returns the Cardano type associated with this instance.

        :return: The Cardano type as a string.
        :rtype: str
        """

        return self._cardano_type

    @classmethod
    def is_valid(cls, seed: str, cardano_type: str = Cardano.TYPES.BYRON_ICARUS) -> bool:
        """
        Checks if the given seed is valid.

        :param seed: Hex string representing seed
        :type seed: str
        :param cardano_type: The type of Cardano seed. Defaults to Cardano.TYPES.BYRON_ICARUS.
        :type cardano_type: str, optional

        :return: True if is valid, False otherwise.
        :rtype: bool
        """

        if not isinstance(seed, str) or not bool(re.fullmatch(
            r'^[0-9a-fA-F]+$', seed
        )):
            return False

        if cardano_type in [Cardano.TYPES.BYRON_ICARUS, Cardano.TYPES.SHELLEY_ICARUS]:
            return len(seed) == cls.lengths[0]
        elif cardano_type in [Cardano.TYPES.BYRON_LEDGER, Cardano.TYPES.SHELLEY_LEDGER]:
            return len(seed) == cls.lengths[1]
        elif cardano_type == Cardano.TYPES.BYRON_LEGACY:
            return len(seed) == cls.lengths[2]
        else:
            raise SeedError(
                "Invalid Cardano type", expected=Cardano.TYPES.get_cardano_types(), got=cardano_type
            )

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: Union[str, IMnemonic],
        passphrase: Optional[str] = None,
        language: Optional[str] = None,
        cardano_type: str = Cardano.TYPES.BYRON_ICARUS
    ) -> str:
        """
        Generates a Cardano wallet seed based on the specified cardano_type.

        This method allows generating different types of Cardano wallet seeds based on the `cardano_type` parameter.

        :param mnemonic: The mnemonic phrase to be used for seed generation. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :param passphrase: Optional passphrase used for seed derivation, default is `None`.
        :type passphrase: Optional[str]

        :param cardano_type: Specifies the type of Cardano seed to generate. Default is Byron Icarus.
                             Valid options are defined in `Cardano.TYPES`.
        :type cardano_type: str

        :return: The generated Cardano wallet seed as a string.
        :rtype: str
        """

        if cardano_type == Cardano.TYPES.BYRON_ICARUS:
            return cls.generate_byron_icarus(mnemonic=mnemonic, language=language)
        if cardano_type == Cardano.TYPES.BYRON_LEDGER:
            return cls.generate_byron_ledger(
                mnemonic=mnemonic, passphrase=passphrase, language=language,
            )
        if cardano_type == Cardano.TYPES.BYRON_LEGACY:
            return cls.generate_byron_legacy(mnemonic=mnemonic, language=language)
        if cardano_type == Cardano.TYPES.SHELLEY_ICARUS:
            return cls.generate_shelley_icarus(mnemonic=mnemonic, language=language)
        elif cardano_type == Cardano.TYPES.SHELLEY_LEDGER:
            return cls.generate_shelley_ledger(
                mnemonic=mnemonic, passphrase=passphrase, language=language
            )
        raise Error(
            "Invalid Cardano type", expected=Cardano.TYPES.get_cardano_types(), got=cardano_type
        )

    @classmethod
    def generate_byron_icarus(cls, mnemonic: Union[str, IMnemonic], language: Optional[str] = None) -> str:
        """
        Generates a Byron Icarus seed from a given mnemonic phrase.

        :param mnemonic: The mnemonic phrase to be used for seed generation. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :return: The derived Byron Icarus seed as a string.
        :rtype: str
        """
        if not isinstance(mnemonic, IMnemonic):
            mnemonic = BIP39Mnemonic(mnemonic=mnemonic, language=language)
        assert isinstance(mnemonic, BIP39Mnemonic)

        return BIP39Mnemonic.decode(mnemonic=mnemonic.mnemonic(), language=mnemonic.language())

    @classmethod
    def generate_byron_ledger(cls, mnemonic: Union[str, IMnemonic], passphrase: Optional[str] = None, language: Optional[str] = None) -> str:
        """
        Generates a Byron Ledger seed from a given mnemonic phrase and optional passphrase.

        :param mnemonic: The mnemonic phrase to be used for seed generation. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :param passphrase: An optional passphrase to be used in the seed generation process.
        :type passphrase: Optional[str]

        :return: The derived Byron Ledger seed as a string.
        :rtype: str
        """
        if not isinstance(mnemonic, IMnemonic):
            mnemonic = BIP39Mnemonic(mnemonic=mnemonic, language=language)
        assert isinstance(mnemonic, BIP39Mnemonic)

        return BIP39Seed.from_mnemonic(mnemonic=mnemonic.mnemonic(), language=mnemonic.language(), passphrase=passphrase)

    @classmethod
    def generate_byron_legacy(cls, mnemonic: Union[str, IMnemonic], language: Optional[str] = None) -> str:
        """
        Generates a Byron Legacy seed from a given mnemonic phrase.

        :param mnemonic: The mnemonic phrase to be used for seed generation. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :return: The derived Byron Legacy seed as a string.
        :rtype: str
        """
        if not isinstance(mnemonic, IMnemonic):
            mnemonic = BIP39Mnemonic(mnemonic=mnemonic, language=language)
        assert isinstance(mnemonic, BIP39Mnemonic)

        return bytes_to_string(blake2b_256(
            cbor2.dumps(get_bytes(BIP39Mnemonic.decode(mnemonic=mnemonic.mnemonic(), language=mnemonic.language())))
        ))

    @classmethod
    def generate_shelley_icarus(cls, mnemonic: Union[str, IMnemonic], language: Optional[str] = None) -> str:
        """
        Generates a Shelley Icarus seed from a given mnemonic phrase.

        :param mnemonic: The mnemonic phrase to be used for seed generation. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]

        :return: The derived Shelley Icarus seed as a string.
        :rtype: str
        """

        return cls.generate_byron_icarus(
            mnemonic=mnemonic, language=language
        )

    @classmethod
    def generate_shelley_ledger(cls, mnemonic: str, passphrase: Optional[str] = None, language: Optional[str] = None) -> str:
        """
        Generates a Shelley ledger seed from a given mnemonic phrase and optional passphrase.

        :param mnemonic: The mnemonic phrase to be used for seed generation.
        :type mnemonic: str
        :param passphrase: An optional passphrase to strengthen the security of the seed. Defaults to None.
        :type passphrase: Optional[str]

        :return: The derived Shelley ledger seed as a string.
        :rtype: str
        """

        return cls.generate_byron_ledger(
            mnemonic=mnemonic, passphrase=passphrase, language=language
        )
