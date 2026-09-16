#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from abc import (
    ABC, abstractmethod
)
from typing import (
    Union, Dict, List, Tuple, Optional
)

import os

from ..exceptions import MnemonicError
from ..entropies import IEntropy


class IMnemonic(ABC):

    _mnemonic: List[str]
    _words: int
    _language: str
    _mnemonic_type: Optional[str]

    words_list: List[int]
    languages: List[str]
    wordlist_path: Dict[str, str]

    def __init__(self, mnemonic: Union[str, List[str]], **kwargs) -> None:
        """
        Initialize an instance of IMnemonic with a mnemonic.

        :param mnemonic: The mnemonic to initialize with, which can be a string or a list of strings.
        :type mnemonic: Union[str, List[str]]
        :param kwargs: Additional keyword arguments.

        :return: No return
        :rtype: NoneType
        """

        self._mnemonic: List[str] = self.normalize(mnemonic)
        if not self.is_valid(self._mnemonic, **kwargs):
            raise MnemonicError("Invalid mnemonic words")

        _, self._language = self.find_language(self._mnemonic)
        self._mnemonic_type = kwargs.get("mnemonic_type", None)
        self._words = len(self._mnemonic)

    @classmethod
    def name(cls) -> str:
        pass

    def mnemonic(self) -> str:
        """
        Get the mnemonic as a single string.

        :return: The mnemonic as a single string joined by spaces.
        :rtype: str
        """

        return " ".join(self._mnemonic)

    def mnemonic_type(self) -> str:
        """
        Retrieves the type of the mnemonic.

        :return: The type of the mnemonic.
        :rtype: str
        """

        raise NotImplemented

    def language(self) -> str:
        """
        Get the formatted language value.

        :return: The formatted language string where each part is capitalized.
        :rtype: str
        """
        return self._language

    def words(self) -> int:
        """
        :return: The words.
        :rtype: int
        """

        return self._words

    @classmethod
    @abstractmethod
    def from_words(cls, words: int, language: str) -> str:
        pass

    @classmethod
    @abstractmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, **kwargs) -> str:
        pass

    @classmethod
    @abstractmethod
    def encode(cls, entropy: Union[str, bytes], language: str) -> str:
        pass

    @classmethod
    @abstractmethod
    def decode(cls, mnemonic: Union[str, List[str]], **kwargs) -> str:
        pass

    @classmethod
    def get_words_list_by_language(
        cls, language: str, wordlist_path: Optional[Dict[str, str]] = None
    ) -> List[str]:
        """
        Retrieves the word list for the specified language.

        :param language: The language for which to get the word list.
        :type language: str
        :param wordlist_path: Optional dictionary mapping language names to file paths of their word lists.
        :type wordlist_path: Optional[Dict[str, str]]

        :return: A list of words for the specified language.
        :rtype: List[str]
        """

        wordlist_path = cls.wordlist_path if wordlist_path is None else wordlist_path
        with open(os.path.join(os.path.dirname(__file__), wordlist_path[language]), "r", encoding="utf-8") as fin:
            words_list: List[str] = [
                word.strip() for word in fin.readlines() if word.strip() != "" and not word.startswith("#")
            ]
        return words_list

    @classmethod
    def find_language(
        cls, mnemonic: List[str], wordlist_path: Optional[Dict[str, str]] = None
    ) -> Union[str, Tuple[List[str], str]]:
        """
        Finds the language of the given mnemonic by checking against available word lists.

        :param mnemonic: The mnemonic to check, represented as a list of words.
        :type mnemonic: List[str]
        :param wordlist_path: Optional dictionary mapping language names to file paths of their word lists.
        :type wordlist_path: Optional[Dict[str, str]]

        :return: A tuple containing the word list and the language name if found.
        :rtype: Union[str, Tuple[List[str], str]]
        """

        for language in cls.languages:
            try:
                words_list: list = cls.normalize(
                    cls.get_words_list_by_language(
                        language=language, wordlist_path=wordlist_path
                    )
                )
                words_list_with_index: dict = {
                    words_list[i]: i for i in range(len(words_list))
                }
                for word in mnemonic:
                    try:
                        words_list_with_index[word]
                    except KeyError as ex:
                        raise MnemonicError(f"Unable to find word {word}") from ex
                return words_list, language
            except (MnemonicError, ValueError):
                continue
        raise MnemonicError(f"Invalid language for mnemonic '{mnemonic}'")

    @classmethod
    def is_valid(cls, mnemonic: Union[str, List[str]], **kwargs) -> bool:
        """
        Checks if the given mnemonic is valid.

        :param mnemonic: The mnemonic to check.
        :type mnemonic: str
        :param kwargs: Additional keyword arguments.

        :return: True if the strength is valid, False otherwise.
        :rtype: bool
        """

        try:
            cls.decode(mnemonic=mnemonic, **kwargs)
            return True
        except (ValueError, MnemonicError):
            return False

    @classmethod
    def is_valid_language(cls, language: str) -> bool:
        """
        Checks if the given language is valid.

        :param language: The language to check.
        :type language: str

        :return: True if the strength is valid, False otherwise.
        :rtype: bool
        """

        return language in cls.languages

    @classmethod
    def is_valid_words(cls, words: int) -> bool:
        """
        Checks if the given words is valid.

        :param words: The words to check.
        :type words: int

        :return: True if the strength is valid, False otherwise.
        :rtype: bool
        """

        return words in cls.words_list

    @classmethod
    def normalize(cls, mnemonic: Union[str, List[str]]) -> List[str]:
        """
        Normalizes the given mnemonic by splitting it into a list of words if it is a string.

        :param mnemonic: The mnemonic value, which can be a single string of words or a list of words.
        :type mnemonic: Union[str, List[str]]

        :return: A list of words from the mnemonic.
        :rtype: List[str]
        """

        return mnemonic.split() if isinstance(mnemonic, str) else mnemonic
