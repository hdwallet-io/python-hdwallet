#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from abc import (
    ABC, abstractmethod
)
from typing import Optional, Union

import re

from ..mnemonics import IMnemonic


class ISeed(ABC):

    _name: str
    _seed: str

    length: int

    def __init__(self, seed: str, **kwargs) -> None:
        """
        Initialize an object with a seed value.

        :param seed: The seed value used for initialization.
        :type seed: str

        :return: No return
        :rtype: NoneType
        """

        self._seed = seed

    @classmethod
    def name(cls) -> str:
        pass

    @classmethod
    def is_valid(cls, seed: str) -> bool:
        """
        Checks if the given seed is valid.

        :param seed: Hex string representing seed
        :type seed: str

        :return: True if is valid, False otherwise.
        :rtype: bool
        """

        return isinstance(seed, str) and bool(re.fullmatch(
            r'^[0-9a-fA-F]+$', seed
        )) and len(seed) * 4 == cls.length

    def seed(self) -> str:
        """
        Retrieves the seed associated with the current instance.

        :return: The seed as a string.
        :rtype: str
        """

        return self._seed

    @classmethod
    @abstractmethod
    def from_mnemonic(cls, mnemonic: Union[str, IMnemonic], language: Optional[str], **kwargs) -> str:
        """
        Retrieves the seed associated with the Mnemonic.

        :param mnemonic: The mnemonic phrase to be decoded. Can be a string or an instance of `IMnemonic`.
        :type mnemonic: Union[str, IMnemonic]
        :param language: The preferred language, if known
        :type language: Optional[str]

        :return: The seed as a string.
        :rtype: str
        """
        pass
