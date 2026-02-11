#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit
import unicodedata

from typing import (
    Union, Dict, List, Mapping, Optional
)

from ...entropies import (
    IEntropy, MoneroEntropy, MONERO_ENTROPY_STRENGTHS
)
from ...crypto import crc32
from ...exceptions import (
    Error, EntropyError, MnemonicError, ChecksumError
)
from ...utils import (
    get_bytes, bytes_to_string, bytes_to_integer, bytes_chunk_to_words, words_to_bytes_chunk
)
from ..imnemonic import IMnemonic


class MONERO_MNEMONIC_WORDS:
    """
    Constants for Monero mnemonic words.
    """

    TWELVE: int = 12
    THIRTEEN: int = 13
    TWENTY_FOUR: int = 24
    TWENTY_FIVE: int = 25


class MONERO_MNEMONIC_LANGUAGES:
    """
    Constants for Monero mnemonic languages.
    """

    CHINESE_SIMPLIFIED: str = "chinese-simplified"
    DUTCH: str = "dutch"
    ENGLISH: str = "english"
    FRENCH: str = "french"
    GERMAN: str = "german"
    ITALIAN: str = "italian"
    JAPANESE: str = "japanese"
    PORTUGUESE: str = "portuguese"
    RUSSIAN: str = "russian"
    SPANISH: str = "spanish"


class MoneroMnemonic(IMnemonic):
    """
    Designed for Monero's mnemonic system, focusing on privacy and security,
    enabling users to recover their wallets through unique seed phrases.

    Here are available ``MONERO_MNEMONIC_WORDS``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWELVE                | 12                   |
    +-----------------------+----------------------+
    | THIRTEEN              | 13                   |
    +-----------------------+----------------------+
    | TWENTY_FOUR           | 24                   |
    +-----------------------+----------------------+
    | TWENTY_FIVE           | 25                   |
    +-----------------------+----------------------+

    Here are available ``MONERO_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | CHINESE_SIMPLIFIED    | chinese-simplified   |
    +-----------------------+----------------------+
    | DUTCH                 | dutch                |
    +-----------------------+----------------------+
    | ENGLISH               | english              |
    +-----------------------+----------------------+
    | FRENCH                | french               |
    +-----------------------+----------------------+
    | GERMAN                | chinese-german       |
    +-----------------------+----------------------+
    | ITALIAN               | italian              |
    +-----------------------+----------------------+
    | JAPANESE              | japanese             |
    +-----------------------+----------------------+
    | PORTUGUESE            | portuguese           |
    +-----------------------+----------------------+
    | RUSSIAN               | russian              |
    +-----------------------+----------------------+
    | SPANISH               | spanish              |
    +-----------------------+----------------------+
    """

    word_bit_length: int = 11
    words_list_number: int = 1626
    words_list: List[int] = [
        MONERO_MNEMONIC_WORDS.TWELVE,
        MONERO_MNEMONIC_WORDS.THIRTEEN,
        MONERO_MNEMONIC_WORDS.TWENTY_FOUR,
        MONERO_MNEMONIC_WORDS.TWENTY_FIVE
    ]
    words_checksum: List[int] = [
        MONERO_MNEMONIC_WORDS.THIRTEEN,
        MONERO_MNEMONIC_WORDS.TWENTY_FIVE
    ]
    words_to_entropy_strength: Dict[int, int] = {
        MONERO_MNEMONIC_WORDS.TWELVE: MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        MONERO_MNEMONIC_WORDS.THIRTEEN: MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        MONERO_MNEMONIC_WORDS.TWENTY_FOUR: MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX,
        MONERO_MNEMONIC_WORDS.TWENTY_FIVE: MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    }
    languages: List[str] = [
        MONERO_MNEMONIC_LANGUAGES.ENGLISH,
        MONERO_MNEMONIC_LANGUAGES.FRENCH,
        MONERO_MNEMONIC_LANGUAGES.SPANISH,
        MONERO_MNEMONIC_LANGUAGES.GERMAN,
        MONERO_MNEMONIC_LANGUAGES.DUTCH,
        MONERO_MNEMONIC_LANGUAGES.ITALIAN,
        MONERO_MNEMONIC_LANGUAGES.RUSSIAN,
        MONERO_MNEMONIC_LANGUAGES.PORTUGUESE,
        MONERO_MNEMONIC_LANGUAGES.JAPANESE,
        MONERO_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED,
    ]
    language_unique_prefix_lengths: Dict[str, int] = {
        MONERO_MNEMONIC_LANGUAGES.ENGLISH: 3,
        MONERO_MNEMONIC_LANGUAGES.FRENCH: 4,
        MONERO_MNEMONIC_LANGUAGES.SPANISH: 4,
        MONERO_MNEMONIC_LANGUAGES.GERMAN: 4,
        MONERO_MNEMONIC_LANGUAGES.DUTCH: 4,
        MONERO_MNEMONIC_LANGUAGES.ITALIAN: 4,
        MONERO_MNEMONIC_LANGUAGES.RUSSIAN: 4,
        MONERO_MNEMONIC_LANGUAGES.PORTUGUESE: 4,
        MONERO_MNEMONIC_LANGUAGES.JAPANESE: 4,
        MONERO_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED: 1,
    }
    wordlist_path: Dict[str, str] = {
        MONERO_MNEMONIC_LANGUAGES.ENGLISH: "monero/wordlist/english.txt",
        MONERO_MNEMONIC_LANGUAGES.FRENCH: "monero/wordlist/french.txt",
        MONERO_MNEMONIC_LANGUAGES.SPANISH: "monero/wordlist/spanish.txt",
        MONERO_MNEMONIC_LANGUAGES.GERMAN: "monero/wordlist/german.txt",
        MONERO_MNEMONIC_LANGUAGES.DUTCH: "monero/wordlist/dutch.txt",
        MONERO_MNEMONIC_LANGUAGES.ITALIAN: "monero/wordlist/italian.txt",
        MONERO_MNEMONIC_LANGUAGES.RUSSIAN: "monero/wordlist/russian.txt",
        MONERO_MNEMONIC_LANGUAGES.PORTUGUESE: "monero/wordlist/portuguese.txt",
        MONERO_MNEMONIC_LANGUAGES.JAPANESE: "monero/wordlist/japanese.txt",
        MONERO_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED: "monero/wordlist/chinese_simplified.txt",
    }

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the entropy class.
        :rtype: str
        """
        return "Monero"

    @classmethod
    def from_words(cls, words: int, language: str) -> str:
        """
        Generates a mnemonic phrase from a specified number of words and language.

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
            entropy=MoneroEntropy.generate(cls.words_to_entropy_strength[words]),
            language=language,
            checksum=(
                True if words in cls.words_checksum else False
            )
        )

    @classmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, checksum: bool = False) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str
        :param checksum: Whether to include a checksum in the mnemonic phrase.
        :type checksum: bool

        :return: The generated mnemonic phrase.
        :rtype: str
        """
        if isinstance(entropy, str) or isinstance(entropy, bytes):
            return cls.encode(
                entropy=entropy, language=language, checksum=checksum
            )
        elif isinstance(entropy, MoneroEntropy):
            return cls.encode(
                entropy=entropy.entropy(), language=language, checksum=checksum
            )
        raise EntropyError(
            "Invalid entropy instance", expected=[str, bytes, MoneroEntropy], got=type(entropy)
        )

    @classmethod
    def encode(cls, entropy: Union[str, bytes], language: str, checksum: bool = False) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str
        :param checksum: Whether to include a checksum in the mnemonic phrase.
        :type checksum: bool

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        entropy: bytes = get_bytes(entropy)
        if not MoneroEntropy.is_valid_bytes_strength(len(entropy)):
            raise EntropyError(
                "Wrong entropy strength", expected=MoneroEntropy.strengths, got=(len(entropy) * 8)
            )

        mnemonic: List[str] = []
        words_list: List[str] = cls.get_words_list_by_language(language=language)  # NFKC normalized
        if len(words_list) != cls.words_list_number:
            raise Error(
                "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list)
            )

        for index in range(len(get_bytes(entropy)) // 4):
            mnemonic += bytes_chunk_to_words(
                entropy[index * 4:(index * 4) + 4], words_list, "little"
            )

        if checksum:
            unique_prefix_length = cls.language_unique_prefix_lengths[language]
            prefixes = "".join(unicodedata.normalize("NFD", word)[:unique_prefix_length] for word in mnemonic)
            checksum_word = mnemonic[
                bytes_to_integer(crc32(prefixes)) % len(mnemonic)
            ]
            mnemonic = mnemonic + [checksum_word]

        return " ".join(cls.normalize(mnemonic))

    @classmethod
    def decode(
        cls,
        mnemonic: str,
        language: Optional[str] = None,
        words_list: Optional[List[str]] = None,
        words_list_with_index: Optional[Mapping[str, int]] = None,
        **kwargs
    ) -> str:
        """
        Decodes a mnemonic phrase into entropy data.

        :param mnemonic: The mnemonic phrase to decode.
        :type mnemonic: str
        :param language: The preferred mnemonic language.
        :type language: str
        :param kwargs: Additional keyword arguments (checksum).

        :return: The decoded entropy data.
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
                if len(words) in cls.words_checksum:
                    mnemonic: list = words[:-1]
                    unique_prefix_length = cls.language_unique_prefix_lengths[language]
                    prefixes = "".join(unicodedata.normalize("NFD", word)[:unique_prefix_length] for word in mnemonic)
                    checksum_word = mnemonic[
                        bytes_to_integer(crc32(prefixes)) % len(mnemonic)
                    ]
                    if words[-1] != checksum_word:
                        raise ChecksumError(
                            "Invalid checksum", expected=checksum_word, got=words[-1]
                        )
                
                entropy: bytes = b""
                for index in range(len(words) // 3):
                    word_1, word_2, word_3 = words[index * 3:(index * 3) + 3]
                    entropy += words_to_bytes_chunk(
                        word_1, word_2, word_3, word_indices.keys(), "little"
                    )
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
