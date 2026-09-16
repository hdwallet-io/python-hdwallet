#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Dict, List, Optional
)

import unicodedata

from ...entropies import (
    IEntropy, BIP39Entropy, BIP39_ENTROPY_STRENGTHS
)
from ...crypto import sha256
from ...exceptions import (
    Error, EntropyError, MnemonicError, ChecksumError
)
from ...utils import (
    get_bytes,
    bytes_to_binary_string,
    bytes_to_string,
    binary_string_to_integer,
    integer_to_binary_string,
    binary_string_to_bytes
)
from ..imnemonic import IMnemonic


class BIP39_MNEMONIC_WORDS:

    TWELVE: int = 12
    FIFTEEN: int = 15
    EIGHTEEN: int = 18
    TWENTY_ONE: int = 21
    TWENTY_FOUR: int = 24


class BIP39_MNEMONIC_LANGUAGES:

    CHINESE_SIMPLIFIED: str = "chinese-simplified"
    CHINESE_TRADITIONAL: str = "chinese-traditional"
    CZECH: str = "czech"
    ENGLISH: str = "english"
    FRENCH: str = "french"
    ITALIAN: str = "italian"
    JAPANESE: str = "japanese"
    KOREAN: str = "korean"
    PORTUGUESE: str = "portuguese"
    RUSSIAN: str = "russian"
    SPANISH: str = "spanish"
    TURKISH: str = "turkish"


class BIP39Mnemonic(IMnemonic):
    """
    Implements the BIP39 standard, allowing the creation of mnemonic phrases for
    generating deterministic keys, widely used across various cryptocurrencies.

    Here are available ``BIP39_MNEMONIC_WORDS``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWELVE                | 12                   |
    +-----------------------+----------------------+
    | FIFTEEN               | 15                   |
    +-----------------------+----------------------+
    | EIGHTEEN              | 18                   |
    +-----------------------+----------------------+
    | TWENTY_ONE            | 21                   |
    +-----------------------+----------------------+
    | TWENTY_FOUR           | 24                   |
    +-----------------------+----------------------+

    Here are available ``BIP39_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | CHINESE_SIMPLIFIED    | chinese-simplified   |
    +-----------------------+----------------------+
    | CHINESE_TRADITIONAL   | chinese-traditional  |
    +-----------------------+----------------------+
    | CZECH                 | czech                |
    +-----------------------+----------------------+
    | ENGLISH               | english              |
    +-----------------------+----------------------+
    | FRENCH                | french               |
    +-----------------------+----------------------+
    | ITALIAN               | italian              |
    +-----------------------+----------------------+
    | JAPANESE              | japanese             |
    +-----------------------+----------------------+
    | KOREAN                | korean               |
    +-----------------------+----------------------+
    | PORTUGUESE            | portuguese           |
    +-----------------------+----------------------+
    | RUSSIAN               | russian              |
    +-----------------------+----------------------+
    | SPANISH               | spanish              |
    +-----------------------+----------------------+
    | TURKISH               | turkish              |
    +-----------------------+----------------------+
    """

    word_bit_length: int = 11
    words_list_number: int = 2048
    words_list: List[int] = [
        BIP39_MNEMONIC_WORDS.TWELVE,
        BIP39_MNEMONIC_WORDS.FIFTEEN,
        BIP39_MNEMONIC_WORDS.EIGHTEEN,
        BIP39_MNEMONIC_WORDS.TWENTY_ONE,
        BIP39_MNEMONIC_WORDS.TWENTY_FOUR
    ]
    words_to_entropy_strength: Dict[int, int] = {
        BIP39_MNEMONIC_WORDS.TWELVE: BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        BIP39_MNEMONIC_WORDS.FIFTEEN: BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_SIXTY,
        BIP39_MNEMONIC_WORDS.EIGHTEEN: BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_NINETY_TWO,
        BIP39_MNEMONIC_WORDS.TWENTY_ONE: BIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_TWENTY_FOUR,
        BIP39_MNEMONIC_WORDS.TWENTY_FOUR: BIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    }
    languages: List[str] = [
        BIP39_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED,
        BIP39_MNEMONIC_LANGUAGES.CHINESE_TRADITIONAL,
        BIP39_MNEMONIC_LANGUAGES.CZECH,
        BIP39_MNEMONIC_LANGUAGES.ENGLISH,
        BIP39_MNEMONIC_LANGUAGES.FRENCH,
        BIP39_MNEMONIC_LANGUAGES.ITALIAN,
        BIP39_MNEMONIC_LANGUAGES.JAPANESE,
        BIP39_MNEMONIC_LANGUAGES.KOREAN,
        BIP39_MNEMONIC_LANGUAGES.PORTUGUESE,
        BIP39_MNEMONIC_LANGUAGES.RUSSIAN,
        BIP39_MNEMONIC_LANGUAGES.SPANISH,
        BIP39_MNEMONIC_LANGUAGES.TURKISH
    ]
    wordlist_path: Dict[str, str] = {
        BIP39_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED: "bip39/wordlist/chinese_simplified.txt",
        BIP39_MNEMONIC_LANGUAGES.CHINESE_TRADITIONAL: "bip39/wordlist/chinese_traditional.txt",
        BIP39_MNEMONIC_LANGUAGES.CZECH: "bip39/wordlist/czech.txt",
        BIP39_MNEMONIC_LANGUAGES.ENGLISH: "bip39/wordlist/english.txt",
        BIP39_MNEMONIC_LANGUAGES.FRENCH: "bip39/wordlist/french.txt",
        BIP39_MNEMONIC_LANGUAGES.ITALIAN: "bip39/wordlist/italian.txt",
        BIP39_MNEMONIC_LANGUAGES.JAPANESE: "bip39/wordlist/japanese.txt",
        BIP39_MNEMONIC_LANGUAGES.KOREAN: "bip39/wordlist/korean.txt",
        BIP39_MNEMONIC_LANGUAGES.PORTUGUESE: "bip39/wordlist/portuguese.txt",
        BIP39_MNEMONIC_LANGUAGES.RUSSIAN: "bip39/wordlist/russian.txt",
        BIP39_MNEMONIC_LANGUAGES.SPANISH: "bip39/wordlist/spanish.txt",
        BIP39_MNEMONIC_LANGUAGES.TURKISH: "bip39/wordlist/turkish.txt"
    }

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the entropy class.
        :rtype: str
        """
        return "BIP39"

    @classmethod
    def from_words(cls, words: int, language: str) -> str:
        """
        Generates a mnemonic phrase from a specified number of words.

        This method generates a mnemonic phrase based on the specified number of words and language.

        :param words: The number of words for the mnemonic phrase.
        :type words: int
        :param language: The language for the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """
        if words not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words number", expected=cls.words_list, got=words)

        return cls.from_entropy(
            entropy=BIP39Entropy.generate(cls.words_to_entropy_strength[words]), language=language
        )

    @classmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, **kwargs) -> str:
        """
        Generates from entropy data.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """
        if isinstance(entropy, str) or isinstance(entropy, bytes):
            return cls.encode(entropy=entropy, language=language)
        elif isinstance(entropy, BIP39Entropy):
            return cls.encode(entropy=entropy.entropy(), language=language)
        raise EntropyError(
            "Invalid entropy instance", expected=[str, bytes, BIP39Entropy], got=type(entropy)
        )

    @classmethod
    def encode(cls, entropy: Union[str, bytes], language: str) -> str:
        """
        Encodes entropy into a mnemonic phrase.

        This method converts a given entropy value into a mnemonic phrase according to the specified language.

        :param entropy: The entropy to encode into a mnemonic phrase.
        :type entropy: Union[str, bytes]
        :param language: The language for the mnemonic phrase.
        :type language: str

        :return: The encoded mnemonic phrase.
        :rtype: str
        """

        entropy: bytes = get_bytes(entropy)
        if not BIP39Entropy.is_valid_bytes_strength(len(entropy)):
            raise EntropyError(
                "Wrong entropy strength", expected=BIP39Entropy.strengths, got=(len(entropy) * 8)
            )

        entropy_binary_string: str = bytes_to_binary_string(get_bytes(entropy), len(entropy) * 8)
        entropy_hash_binary_string: str = bytes_to_binary_string(sha256(entropy), 32 * 8)
        mnemonic_bin: str = entropy_binary_string + entropy_hash_binary_string[:len(entropy) // 4]

        mnemonic: List[str] = []
        words_list: List[str] = cls.normalize(cls.get_words_list_by_language(language=language))
        if len(words_list) != cls.words_list_number:
            raise Error(
                "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list)
            )

        for index in range(len(mnemonic_bin) // cls.word_bit_length):
            word_bin: str = mnemonic_bin[index * cls.word_bit_length:(index + 1) * cls.word_bit_length]
            word_index: int = binary_string_to_integer(word_bin)
            mnemonic.append(words_list[word_index])

        return " ".join(cls.normalize(mnemonic))

    @classmethod
    def decode(
        cls, mnemonic: str, checksum: bool = False, words_list: Optional[List[str]] = None, words_list_with_index: Optional[dict] = None
    ) -> str:
        """
        Decodes a mnemonic phrase into its corresponding entropy.

        This method converts a given mnemonic phrase back into its original entropy value.
        It also verifies the checksum to ensure the mnemonic is valid.

        :param mnemonic: The mnemonic phrase to decode.
        :type mnemonic: str
        :param checksum: Whether to include the checksum in the returned entropy.
        :type checksum: bool
        :param words_list: Optional list of words used to decode the mnemonic. If not provided, the method will use the default word list for the language detected.
        :type words_list: Optional[List[str]]
        :param words_list_with_index: Optional dictionary mapping words to their indices for decoding. If not provided, the method will use the default mapping.
        :type words_list_with_index: Optional[dict]

        :return: The decoded entropy as a string.
        :rtype: str
        """

        words: list = cls.normalize(mnemonic)
        if len(words) not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words count", expected=cls.words_list, got=len(words))

        if not words_list or not words_list_with_index:
            words_list, language = cls.find_language(mnemonic=words)
            if len(words_list) != cls.words_list_number:
                raise Error(
                    "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list)
                )
            words_list_with_index: dict = {
                words_list[i]: i for i in range(len(words_list))
            }

        if len(words_list) != cls.words_list_number:
            raise Error(
                "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list)
            )

        mnemonic_bin: str = "".join(map(
            lambda word: integer_to_binary_string(
                words_list_with_index[word], cls.word_bit_length
            ), words
        ))

        mnemonic_bit_length: int = len(mnemonic_bin)
        checksum_length: int = mnemonic_bit_length // 33
        checksum_bin: str = mnemonic_bin[-checksum_length:]
        entropy: bytes = binary_string_to_bytes(
            mnemonic_bin[:-checksum_length], checksum_length * 8
        )
        entropy_hash_bin: str = bytes_to_binary_string(
            sha256(entropy), 32 * 8
        )
        checksum_bin_got: str = entropy_hash_bin[:checksum_length]
        if checksum_bin != checksum_bin_got:
            raise ChecksumError(
                "Invalid checksum", expected=checksum_bin, got=checksum_bin_got
            )

        if checksum:
            pad_bit_len: int = (
                mnemonic_bit_length
                if mnemonic_bit_length % 8 == 0 else
                mnemonic_bit_length + (8 - mnemonic_bit_length % 8)
            )
            return bytes_to_string(
                binary_string_to_bytes(mnemonic_bin, pad_bit_len // 4)
            )
        return bytes_to_string(entropy)

    @classmethod
    def is_valid(
        cls,
        mnemonic: Union[str, List[str]],
        words_list: Optional[List[str]] = None,
        words_list_with_index: Optional[dict] = None
    ) -> bool:
        """
        Validates a mnemonic phrase.

        This method checks whether the provided mnemonic phrase is valid by attempting to decode it.
        If the decoding is successful without raising any errors, the mnemonic is considered valid.

        :param mnemonic: The mnemonic phrase to validate. It can be a string or a list of words.
        :type mnemonic: Union[str, List[str]]
        :param words_list: Optional list of words to be used for validation. If not provided, the method will use the default word list.
        :type words_list: Optional[List[str]]
        :param words_list_with_index: Optional dictionary mapping words to their indices for validation. If not provided, the method will use the default mapping.
        :type words_list_with_index: Optional[dict]

        :return: True if the mnemonic phrase is valid, False otherwise.
        :rtype: bool
        """

        try:
            cls.decode(
                mnemonic=mnemonic, words_list=words_list, words_list_with_index=words_list_with_index
            )
            return True
        except (Error, KeyError):
            return False

    @classmethod
    def normalize(cls, mnemonic: Union[str, List[str]]) -> List[str]:
        """
        Normalizes the given mnemonic by splitting it into a list of words if it is a string.

        :param mnemonic: The mnemonic value, which can be a single string of words or a list of words.
        :type mnemonic: Union[str, List[str]]

        :return: A list of words from the mnemonic.
        :rtype: List[str]
        """

        mnemonic: list = mnemonic.split() if isinstance(mnemonic, str) else mnemonic
        return list(map(lambda _: unicodedata.normalize("NFKD", _.lower()), mnemonic))
