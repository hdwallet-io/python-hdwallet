#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Dict, List, Mapping, Union, Optional
)

from ....entropies import (
    IEntropy, ElectrumV1Entropy, ELECTRUM_V1_ENTROPY_STRENGTHS
)
from ....exceptions import (
    Error, EntropyError, MnemonicError
)
from ....utils import (
    get_bytes, integer_to_bytes, bytes_to_integer, bytes_to_string
)
from ...imnemonic import IMnemonic


class ELECTRUM_V1_MNEMONIC_WORDS:
    """
    Constants for electrum v1 mnemonic words.
    """

    TWELVE: int = 12


class ELECTRUM_V1_MNEMONIC_LANGUAGES:
    """
    Constants for electrum v1 mnemonic languages.
    """

    ENGLISH: str = "english"


class ElectrumV1Mnemonic(IMnemonic):
    """
    Manages the first version of Electrum mnemonics, used for seed phrases
    in the Electrum Bitcoin wallet, providing a simple and efficient way
    to backup keys.

    Here are available ``ELECTRUM_V1_MNEMONIC_WORDS``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWELVE                | 12                   |
    +-----------------------+----------------------+

    Here are available ``ELECTRUM_V1_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | ENGLISH               | english              |
    +-----------------------+----------------------+
    """

    words_list: List[int] = [
        ELECTRUM_V1_MNEMONIC_WORDS.TWELVE
    ]
    words_to_entropy_strength: Dict[int, int] = {
        ELECTRUM_V1_MNEMONIC_WORDS.TWELVE: ELECTRUM_V1_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT
    }
    languages: List[str] = [
        ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH
    ]
    wordlist_path: Dict[str, str] = {
        ELECTRUM_V1_MNEMONIC_LANGUAGES.ENGLISH: "electrum/v1/wordlist/english.txt"
    }
    words_list_number: int = 1626

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the mnemonic class.
        :rtype: str
        """

        return "Electrum-V1"

    @classmethod
    def from_words(cls, words: int, language: str) -> str:
        """
        Generates a mnemonic phrase from a specified number of words and language.

        This method generates a mnemonic phrase by first validating the number of words against the allowed word list sizes.
        It then generates entropy based on the specified number of words and uses it to create a mnemonic phrase in the
        specified language.

        :param words: The number of words in the mnemonic phrase.
        :type words: int
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        if words not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words number", expected=cls.words_list, got=words)

        return cls.from_entropy(
            entropy=ElectrumV1Entropy.generate(cls.words_to_entropy_strength[words]), language=language
        )

    @classmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, **kwargs) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        This method generates a mnemonic phrase from the given entropy data using the specified language's word list.

        :param entropy: The entropy data used to generate the mnemonic phrase, either as a string or bytes.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        if isinstance(entropy, str) or isinstance(entropy, bytes):
            return cls.encode(entropy=entropy, language=language)
        elif isinstance(entropy, ElectrumV1Entropy):
            return cls.encode(entropy=entropy.entropy(), language=language)
        raise EntropyError(
            "Invalid entropy instance", expected=[str, bytes, ElectrumV1Entropy], got=type(entropy)
        )

    @classmethod
    def encode(cls, entropy: Union[str, bytes], language: str) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        This method generates a mnemonic phrase from the given entropy data using the specified language's word list.

        :param entropy: The entropy data used to generate the mnemonic phrase, either as a string or bytes.
        :type entropy: Union[str, bytes]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        entropy: bytes = get_bytes(entropy)
        if not ElectrumV1Entropy.is_valid_bytes_strength(len(entropy)):
            raise EntropyError(
                "Wrong entropy strength", expected=ElectrumV1Entropy.strengths, got=(len(entropy) * 8)
            )

        mnemonic: List[str] = []
        words_list: List[str] = cls.normalize(cls.get_words_list_by_language(language=language))
        for index in range(len(entropy) // 4):

            chunk: int = bytes_to_integer(
                entropy[index * 4:(index * 4) + 4], endianness="big"
            )
            word_1_index: int = chunk % len(words_list)
            word_2_index: int = (
                ((chunk // len(words_list)) + word_1_index) % len(words_list)
            )
            word_3_index: int = (
                ((chunk // len(words_list) // len(words_list)) + word_2_index) % len(words_list)
            )
            mnemonic += [
                words_list[word_index] for word_index in (word_1_index, word_2_index, word_3_index)
            ]

        return " ".join(cls.normalize(mnemonic))

    @classmethod
    def decode(
        cls,
        mnemonic: str,
        language: Optional[str] = None,
        words_list: Optional[List[str]] = None,
        words_list_with_index: Optional[Mapping[str, int]] = None
    ) -> str:
        """
        Decodes a mnemonic phrase back into entropy data.

        This method decodes the given mnemonic phrase into its original entropy data, using the provided
        word list and index mapping or fetching them based on the mnemonic's language if not provided.

        :param mnemonic: The mnemonic phrase to decode, either as a space-separated string or a list of words.
        :type mnemonic: str
        :param words_list: Optional list of valid words for the mnemonic phrase, normalized and in the correct order.
                           If not provided, uses `cls.get_words_list_by_language` to fetch the list based on the default language.
        :type words_list: Optional[List[str]], optional
        :param words_list_with_index: Optional dictionary mapping words to their indices for quick lookup.
                                      If not provided, constructs this mapping based on `words_list`.
        :type words_list_with_index: Optional[dict], optional

        :return: The decoded entropy data as a byte string.
        :rtype: str
        """

        words: list = cls.normalize(mnemonic)
        if len(words) not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words count", expected=cls.words_list, got=len(words))

        candidates: Mapping[str, Mapping[str, int]] = cls.word_indices_candidates(
            words=words, language=language, words_list=words_list,
            words_list_with_index=words_list_with_index
        )

        exception = None
        entropies: Mapping[Optional[str], str] = {}
        for language, word_indices in candidates.items():
            try:
                entropy: bytes = b""
                for index in range(len(words) // 3):
                    word_1, word_2, word_3 = words[index * 3:(index * 3) + 3]
        
                    word_1_index: int = word_indices[word_1]
                    word_2_index: int = word_indices[word_2] % cls.words_list_number
                    word_3_index: int = word_indices[word_3] % cls.words_list_number
        
                    chunk: int = (
                        word_1_index +
                        (cls.words_list_number * ((word_2_index - word_1_index) % cls.words_list_number)) +
                        (cls.words_list_number * cls.words_list_number * ((word_3_index - word_2_index) % cls.words_list_number))
                    )
                    entropy += integer_to_bytes(chunk, bytes_num=4, endianness="big")
        
                entropies[language] = bytes_to_string(entropy)

            except Exception as exc:
                # Collect first Exception; highest quality languages are first.
                if exception is None:
                    exception = exc

        if entropies:
            (candidate, entropy), *extras = entropies.items()
            if extras:
                exception = MnemonicError(
                    f"Ambiguous languages {', '.join(c for c, _ in extras)} or {candidate} for mnemonic; specify a preferred language"
                )
            else:
                return entropy
        raise exception
