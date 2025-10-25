#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Union, Dict, List, Mapping, Optional
)

from ...entropies import (
    IEntropy, AlgorandEntropy, ALGORAND_ENTROPY_STRENGTHS
)
from ...crypto import sha512_256
from ...exceptions import (
    EntropyError, MnemonicError, ChecksumError
)
from ...utils import (
    get_bytes, bytes_to_string, convert_bits
)
from ..imnemonic import IMnemonic


class ALGORAND_MNEMONIC_WORDS:
    """
    Constants representing algorand mnemonic words.
    """

    TWENTY_FIVE: int = 25


class ALGORAND_MNEMONIC_LANGUAGES:
    """
    Constants representing algorand mnemonic language.
    """

    ENGLISH: str = "english"


class AlgorandMnemonic(IMnemonic):
    """
    Used to generate and manage mnemonics specifically for the Algorand blockchain,
    ensuring secure key derivation and backup.

    Here are available ``ALGORAND_MNEMONIC_WORDS``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWENTY_FIVE           | 25                   |
    +-----------------------+----------------------+

    Here are available ``ALGORAND_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | ENGLISH               | english              |
    +-----------------------+----------------------+
    """

    checksum_length: int = 2
    words_list_number: int = 2048
    words_list: List[int] = [
        ALGORAND_MNEMONIC_WORDS.TWENTY_FIVE
    ]
    words_to_entropy_strength: Dict[int, int] = {
        ALGORAND_MNEMONIC_WORDS.TWENTY_FIVE: ALGORAND_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX
    }
    languages: List[str] = [
        ALGORAND_MNEMONIC_LANGUAGES.ENGLISH
    ]
    wordlist_path: Dict[str, str] = {
        ALGORAND_MNEMONIC_LANGUAGES.ENGLISH: "algorand/wordlist/english.txt"
    }

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the mnemonic class.
        :rtype: str
        """

        return "Algorand"

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
            entropy=AlgorandEntropy.generate(cls.words_to_entropy_strength[words]), language=language
        )

    @classmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, **kwargs) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str

        """
        if isinstance(entropy, str) or isinstance(entropy, bytes):
            return cls.encode(entropy=entropy, language=language)
        elif isinstance(entropy, AlgorandEntropy):
            return cls.encode(entropy=entropy.entropy(), language=language)
        raise EntropyError(
            "Invalid entropy instance", expected=[str, bytes, AlgorandEntropy], got=type(entropy)
        )

    @classmethod
    def encode(cls, entropy: Union[str, bytes], language: str) -> str:
        """
        Encodes entropy data into a mnemonic phrase using the specified language.

        This method converts the provided entropy data into a mnemonic phrase based on the specified language.
        It ensures the entropy has a valid strength and includes a checksum in the mnemonic phrase.

        :param entropy: The entropy data to be encoded. Can be a string or bytes.
        :type entropy: Union[str, bytes]
        :param language: The language for the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        entropy: bytes = get_bytes(entropy)
        if not AlgorandEntropy.is_valid_bytes_strength(len(entropy)):
            raise EntropyError(
                "Wrong entropy strength", expected=AlgorandEntropy.strengths, got=(len(entropy) * 8)
            )

        checksum: bytes = sha512_256(entropy)[:cls.checksum_length]
        checksum_word_indexes: Optional[List[int]] = convert_bits(checksum, 8, 11)
        assert checksum_word_indexes is not None
        word_indexes: Optional[List[int]] = convert_bits(entropy, 8, 11)
        assert word_indexes is not None

        words_list: list = cls.get_words_list_by_language(language=language)
        indexes: list = word_indexes + [checksum_word_indexes[0]]
        return " ".join( words_list[index] for index in indexes )

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
        :param kwargs: Additional keyword arguments (language, checksum).

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
                word_indexes = [word_indices[word] for word in words]
                entropy_list: Optional[List[int]] = convert_bits(word_indexes[:-1], 11, 8)
                assert entropy_list is not None
                entropy: bytes = bytes(entropy_list)[:-1]
        
                checksum: bytes = sha512_256(entropy)[:cls.checksum_length]
                checksum_word_indexes: Optional[List[int]] = convert_bits(checksum, 8, 11)
                assert checksum_word_indexes is not None
                if checksum_word_indexes[0] != word_indexes[-1]:
                    raise ChecksumError(
                        "Invalid checksum", expected=words_list_with_index.keys()[checksum_word_indexes[0]], got=words_list_with_index.keys()[word_indexes[-1]]
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
