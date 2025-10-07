#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Dict, List, Mapping, Union, Optional
)

import unicodedata

from ....entropies import (
    IEntropy, ElectrumV2Entropy, ELECTRUM_V2_ENTROPY_STRENGTHS
)
from ....crypto import hmac_sha512
from ....exceptions import (
    Error, EntropyError, MnemonicError
)
from ....utils import (
    get_bytes, integer_to_bytes, bytes_to_string, bytes_to_integer
)
from ....mnemonics.bip39 import BIP39Mnemonic
from ....mnemonics.electrum.v1 import ElectrumV1Mnemonic
from ...imnemonic import IMnemonic


class ELECTRUM_V2_MNEMONIC_WORDS:
    """
    Constants for electrum v2 mnemonic words.
    """

    TWELVE: int = 12
    TWENTY_FOUR: int = 24


class ELECTRUM_V2_MNEMONIC_LANGUAGES:
    """
    Constants for electrum v2 mnemonic languages.
    """

    CHINESE_SIMPLIFIED: str = "chinese-simplified"
    ENGLISH: str = "english"
    PORTUGUESE: str = "portuguese"
    SPANISH: str = "spanish"


class ELECTRUM_V2_MNEMONIC_TYPES:
    """
    Constants for electrum v2 mnemonic types.
    """

    STANDARD: str = "standard"
    SEGWIT: str = "segwit"
    STANDARD_2FA: str = "standard-2fa"
    SEGWIT_2FA: str = "segwit-2fa"


class ElectrumV2Mnemonic(IMnemonic):
    """
    An update to the ElectrumV1Mnemonic, this class supports the second version
    of Electrum's mnemonic system, offering enhanced features for secure seed
    generation.

    Here are available ``ELECTRUM_V2_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWELVE                | 12                   |
    +-----------------------+----------------------+
    | TWENTY_FOUR           | 24                   |
    +-----------------------+----------------------+

    Here are available ``ELECTRUM_V2_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | ENGLISH               | english              |
    +-----------------------+----------------------+
    | SPANISH               | spanish              |
    +-----------------------+----------------------+
    | PORTUGUESE            | portuguese           |
    +-----------------------+----------------------+
    | CHINESE_SIMPLIFIED    | chinese-simplified   |
    +-----------------------+----------------------+

    Here are available ``ELECTRUM_V2_MNEMONIC_TYPES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | STANDARD              | standard             |
    +-----------------------+----------------------+
    | SEGWIT                | segwit               |
    +-----------------------+----------------------+
    | STANDARD_2FA          | standard-2fa         |
    +-----------------------+----------------------+
    | SEGWIT_2FA            | segwit-2fa           |
    +-----------------------+----------------------+
    """

    word_bit_length: int = 11
    words_list_number: int = 2048
    words_list: List[int] = [
        ELECTRUM_V2_MNEMONIC_WORDS.TWELVE,
        ELECTRUM_V2_MNEMONIC_WORDS.TWENTY_FOUR
    ]
    words_to_entropy_strength: Dict[int, int] = {
        ELECTRUM_V2_MNEMONIC_WORDS.TWELVE: ELECTRUM_V2_ENTROPY_STRENGTHS.ONE_HUNDRED_THIRTY_TWO,
        ELECTRUM_V2_MNEMONIC_WORDS.TWENTY_FOUR: ELECTRUM_V2_ENTROPY_STRENGTHS.TWO_HUNDRED_SIXTY_FOUR
    }
    languages: List[str] = [
        ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH,
        ELECTRUM_V2_MNEMONIC_LANGUAGES.SPANISH,
        ELECTRUM_V2_MNEMONIC_LANGUAGES.PORTUGUESE,
        ELECTRUM_V2_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED,
    ]
    wordlist_path: Dict[str, str] = {
        ELECTRUM_V2_MNEMONIC_LANGUAGES.ENGLISH: "electrum/v2/wordlist/english.txt",
        ELECTRUM_V2_MNEMONIC_LANGUAGES.SPANISH: "electrum/v2/wordlist/spanish.txt",
        ELECTRUM_V2_MNEMONIC_LANGUAGES.PORTUGUESE: "electrum/v2/wordlist/portuguese.txt",
        ELECTRUM_V2_MNEMONIC_LANGUAGES.CHINESE_SIMPLIFIED: "electrum/v2/wordlist/chinese_simplified.txt",
    }
    mnemonic_types: Dict[str, str] = {
        ELECTRUM_V2_MNEMONIC_TYPES.STANDARD: "01",
        ELECTRUM_V2_MNEMONIC_TYPES.SEGWIT: "100",
        ELECTRUM_V2_MNEMONIC_TYPES.STANDARD_2FA: "101",
        ELECTRUM_V2_MNEMONIC_TYPES.SEGWIT_2FA: "102"
    }

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the entropy class.
        :rtype: str
        """
        return "Electrum-V2"

    @classmethod
    def from_words(
        cls,
        words: int,
        language: str,
        mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD,
        max_attempts: int = 10 ** 60
    ) -> str:
        """
        Generates a mnemonic phrase from a specified number of words and language.

        This method generates a mnemonic phrase with a specific number of words in the specified language.
        It ensures the generated mnemonic meets the strength requirements for the given mnemonic type.

        :param words: The number of words in the mnemonic phrase.
        :type words: int
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str
        :param mnemonic_type: The type of mnemonic phrase to generate. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional
        :param max_attempts: The maximum number of attempts to adjust entropy to meet strength requirements.
                             Defaults to 10^60.
        :type max_attempts: int, optional

        :return: The generated mnemonic phrase.
        :rtype: str

        """

        if words not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words number", expected=cls.words_list, got=words)

        return cls.from_entropy(
            entropy=ElectrumV2Entropy.generate(
                cls.words_to_entropy_strength[words]
            ),
            language=language,
            mnemonic_type=mnemonic_type,
            max_attempts=max_attempts
        )

    @classmethod
    def from_entropy(
        cls,
        entropy: Union[str, bytes, IEntropy],
        language: str,
        mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD,
        max_attempts: int = 10 ** 60
    ) -> str:
        """
        Generates a mnemonic phrase from entropy data, ensuring it meets the required strength.

        This method generates a mnemonic phrase from the provided entropy data, validating
        its strength and ensuring it adheres to the specified mnemonic type and language.

        :param entropy: The entropy data used to generate the mnemonic phrase.
                        It can be a string, bytes, or an instance of IEntropy.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str
        :param mnemonic_type: The type of mnemonic phrase to generate. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional
        :param max_attempts: The maximum number of attempts to adjust entropy to meet strength requirements.
                             Defaults to `10^60`.
        :type max_attempts: int, optional

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        if isinstance(entropy, str) or isinstance(entropy, bytes):
            entropy: bytes = get_bytes(entropy)
        elif isinstance(entropy, ElectrumV2Entropy):
            entropy: bytes = get_bytes(entropy.entropy())
        else:
            raise EntropyError(
                "Invalid entropy instance", expected=[str, bytes, ElectrumV2Entropy], got=type(entropy)
            )

        if ElectrumV2Entropy.are_entropy_bits_enough(entropy):

            words_list: List[str] = cls.get_words_list_by_language(
                language=language, wordlist_path=cls.wordlist_path
            )
            bip39_words_indices: Optional[List[str]] = None
            (_, _, bip39_words_indices), = BIP39Mnemonic.wordlist_indices(language=language)
            electrum_v1_words_indices: Optional[List[str]] = None
            try:
                (_, _, electrum_v1_words_indices), = ElectrumV1Mnemonic.wordlist_indices(language=language)
            except ValueError:
                pass

            entropy: int = bytes_to_integer(entropy)
            for index in range(max_attempts):
                new_entropy: int = entropy + index
                try:
                    return cls.encode(
                        entropy=integer_to_bytes(new_entropy),
                        language=language,
                        mnemonic_type=mnemonic_type,
                        words_list=words_list,
                        bip39_words_list_with_index=bip39_words_indices,
                        electrum_v1_words_list_with_index=electrum_v1_words_indices,
                    )
                except EntropyError:
                    continue

        raise Error("Unable to generate a valid mnemonic")

    @classmethod
    def encode(
        cls,
        entropy: Union[str, bytes],
        language: str,
        mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD,
        words_list: Optional[List[str]] = None,
        bip39_words_list: Optional[List[str]] = None,
        bip39_words_list_with_index: Optional[Mapping[str, int]] = None,
        electrum_v1_words_list: Optional[List[str]] = None,
        electrum_v1_words_list_with_index: Optional[Mapping[str, int]] = None
    ) -> str:
        """
        Generates a mnemonic phrase from entropy data.

        This method generates a mnemonic phrase from provided entropy data, ensuring
        it meets the requirements of the specified mnemonic type and language.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes]
        :param language: The language for which to generate the mnemonic phrase.
        :type language: str
        :param mnemonic_type: The type of mnemonic phrase to generate. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional
        :param words_list: Optional list of words to use for generating the mnemonic.
        :type words_list: List[str], optional
        :param bip39_words_list: Optional list of BIP39 words for validation.
        :type bip39_words_list: List[str], optional
        :param bip39_words_list_with_index: Optional dictionary mapping BIP39 words to indices.
        :type bip39_words_list_with_index: dict, optional
        :param electrum_v1_words_list: Optional list of Electrum V1 words for validation.
        :type electrum_v1_words_list: List[str], optional
        :param electrum_v1_words_list_with_index: Optional dictionary mapping Electrum V1 words to indices.
        :type electrum_v1_words_list_with_index: dict, optional

        :return: The generated mnemonic phrase.
        :rtype: str
        """

        entropy: int = bytes_to_integer(get_bytes(entropy))
        if not ElectrumV2Entropy.are_entropy_bits_enough(entropy):
            raise EntropyError("Entropy bit length is not enough for generating a valid mnemonic")

        mnemonic: List[str] = []
        if not words_list:
            words_list = cls.get_words_list_by_language(language=language)
        if len(words_list) != cls.words_list_number:
            raise Error(
                "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list)
            )

        # Produces mnemonics of valid length, even if entropy has trailing zero bits
        while entropy > 0 or len(mnemonic) not in set(cls.words_list):
            word_index: int = entropy % cls.words_list_number
            entropy //= cls.words_list_number
            mnemonic.append(words_list[word_index])

        if not cls.is_valid(
            mnemonic=mnemonic,
            language=language,
            mnemonic_type=mnemonic_type,
            bip39_words_list=bip39_words_list,
            bip39_words_list_with_index=bip39_words_list_with_index,
            electrum_v1_words_list=electrum_v1_words_list,
            electrum_v1_words_list_with_index=electrum_v1_words_list_with_index
        ):
            raise EntropyError("Entropy bytes are not suitable for generating a valid mnemonic")

        return " ".join(mnemonic)  # mnemonic words already NFKC normalized

    @classmethod
    def decode(
        cls,
        mnemonic: str,
        language: Optional[str] = None,
        mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD
    ) -> str:
        """
        Decodes a mnemonic phrase into its original entropy value.

        This method decodes the mnemonic phrase by converting it back into its original
        entropy value, validating its type, and ensuring its integrity.

        :param mnemonic: The mnemonic phrase to decode.
        :type mnemonic: str
        :param mnemonic_type: The type of mnemonic to decode. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional

        :return: The decoded entropy as a string.
        :rtype: str
        """

        words: list = cls.normalize(mnemonic)
        if len(words) not in cls.words_list:
            raise MnemonicError("Invalid mnemonic words count", expected=cls.words_list, got=len(words))

        # if not cls.is_valid(mnemonic, language=language, mnemonic_type=mnemonic_type):
        #     raise MnemonicError(f"Invalid {mnemonic_type} mnemonic type words")

        words_list_with_index, language = cls.find_language(mnemonic=words, language=language)
        if len(words_list_with_index) != cls.words_list_number:
            raise Error(
                "Invalid number of loaded words list", expected=cls.words_list_number, got=len(words_list_with_index)
            )

        entropy: int = 0
        for word in reversed(words):
            entropy: int = (entropy * len(words_list_with_index)) + words_list_with_index[word]

        return bytes_to_string(integer_to_bytes(entropy))

    @classmethod
    def is_valid(
        cls,
        mnemonic: Union[str, List[str]],
        language: Optional[str] = None,
        mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD,
        bip39_words_list: Optional[List[str]] = None,
        bip39_words_list_with_index: Optional[Mapping[str, int]] = None,
        electrum_v1_words_list: Optional[List[str]] = None,
        electrum_v1_words_list_with_index: Optional[Mapping[str, int]] = None
    ) -> bool:
        """
        Checks if the given mnemonic is valid according to the specified mnemonic type.

        This method validates the mnemonic against BIP39 and Electrum V1 mnemonics,
        and then checks if it matches the specified mnemonic type.

        :param mnemonic: The mnemonic phrase to check.
        :type mnemonic: str or List[str]
        :param mnemonic_type: The type of mnemonic to check against. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional
        :param bip39_words_list: Optional list of BIP39 words for validation.
        :type bip39_words_list: List[str], optional
        :param bip39_words_list_with_index: Optional dictionary mapping BIP39 words to indices.
        :type bip39_words_list_with_index: dict, optional
        :param electrum_v1_words_list: Optional list of Electrum V1 words for validation.
        :type electrum_v1_words_list: List[str], optional
        :param electrum_v1_words_list_with_index: Optional dictionary mapping Electrum V1 words to indices.
        :type electrum_v1_words_list_with_index: dict, optional

        :return: True if the mnemonic is valid according to the specified type, False otherwise.
        :rtype: bool
        """

        if BIP39Mnemonic.is_valid(
            mnemonic, language=language, words_list=bip39_words_list, words_list_with_index=bip39_words_list_with_index
        ) or ElectrumV1Mnemonic.is_valid(
            mnemonic, language=language, words_list=electrum_v1_words_list, words_list_with_index=electrum_v1_words_list_with_index
        ):
            return False
        return cls.is_type(
            mnemonic=mnemonic, mnemonic_type=mnemonic_type
        )

    @classmethod
    def is_type(
        cls, mnemonic: Union[str, List[str]], mnemonic_type: str = ELECTRUM_V2_MNEMONIC_TYPES.STANDARD
    ) -> bool:
        """Checks if the given mnemonic matches the specified mnemonic type.

        All seed derivation related functions require NFKD Unicode normalization;
        <IMnemonic>.normalize returns an NFC-normalized list of mnemonic words.

        :param mnemonic: The mnemonic phrase to check.
        :type mnemonic: str or List[str]
        :param mnemonic_type: The type of mnemonic to check against. Defaults to `STANDARD`.
        :type mnemonic_type: str, optional

        :return: True if the mnemonic matches the specified type, False otherwise.
        :rtype: bool

        """
        return bytes_to_string(hmac_sha512(
            b"Seed version", unicodedata.normalize("NFKD", " ".join(cls.normalize(mnemonic)))
        )).startswith(
            cls.mnemonic_types[mnemonic_type]
        )

    def mnemonic_type(self) -> str:
        """
        Retrieves the type of the mnemonic.

        :return: The type of the mnemonic.
        :rtype: str
        """

        return self._mnemonic_type
