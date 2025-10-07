#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from abc import (
    ABC, abstractmethod
)
from collections import (
    abc
)
from typing import (
    Any, Callable, Collection, Dict, Generator, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union
)

import os
import string
import unicodedata
from functools import lru_cache

from collections import defaultdict

from ..exceptions import MnemonicError, ChecksumError
from ..entropies import IEntropy


class TrieError(Exception):
    pass


class Ambiguous(TrieError):
    def __init__(self, message, word: str, options: Set[str]):
        super().__init__( message )
        self.word = word
        self.options = options


class TrieNode:
    """
    Associates a value with a node in a trie.

    The EMPTY marker indicates that a word ending in this TrieNode was not inserted into the True;
    replace with something that will never be provided as a word's 'value', preferably something
    "Falsey".  An insert defaults to PRESENT, preferably something "Truthy".
    """
    EMPTY = None
    PRESENT = True

    def __init__(self):
        self.children: MutableMapping[str, TrieNode] = defaultdict(self.__class__)
        self.value: Any = self.__class__.EMPTY


class Trie:

    def __init__(self, root=None):
        self.root = root if root is not None else TrieNode()

    def insert(self, word: str, value: Optional[Any] = None) -> None:
        """
        Inserts a 'word' into the Trie, associated with 'value'.
        """
        current = self.root
        for letter in word:
            current = current.children[letter]
        assert current.value is current.EMPTY, \
            f"Attempt to re-insert {word!r}; already present with value {current.value!r}"
        current.value = current.PRESENT if value is None else value

    def find(self, word: str, current: Optional[TrieNode] = None) -> Generator[Tuple[bool, str, Optional[TrieNode]], None, None]:
        """Finds all the TrieNode that match the word, optionally from the provided 'current' node.

        If the word isn't in the current Trie, terminates by producing None for the TrieNode.

        """
        if current is None:
            current = self.root
        yield current.value is not current.EMPTY, '', current

        for letter in word:
            current = current.children.get(letter)
            if current is None:
                yield False, '', None
                break
            yield current.value is not current.EMPTY, letter, current

    def complete(self, current: TrieNode) -> Generator[Tuple[bool, str, TrieNode], None, None]:
        """Generate (<completed>, key, node) tuples along an unambiguous path starting from after
        the current TrieNode, until the next terminal TrieNode is encountered.

        Continues until a non-EMPTY value is found, or the path becomes ambiguous.  Tests for a
        terminal value *after* transitioning, so we can use .complete to move from unique terminal
        node to unique terminal node, eg.  'ad' --> 'add' --> 'addict'

        Will only yield candidates that are on an unambiguous path; the final candidate's terminal
        flag must be evaluated to determine if it indicates a completed word was found.

        """
        terminal = False
        while current is not None and not terminal and len( current.children ) == 1:
            # Follow unique path until we hit ambiguity or a terminal (non-empty) node
            (key, current), = current.children.items()
            terminal = current.value is not current.EMPTY
            yield terminal, key, current

    def search(self, word: str, current: Optional[TrieNode] = None, complete: bool = False) -> Tuple[bool, str, Optional[TrieNode]]:
        """Returns the matched stem, and associated TrieNode if the word is in the trie (otherwise None)

        If 'complete' and 'word' is an unambiguous abbreviation of some word with a non-EMPTY value,
        return the node.

        The word could be complete and have a non-EMPTY TrieNode.value, but also could be a prefix
        of other words, so the caller may need to consult the return TrieNode.children.

        """
        stem = ''
        for terminal, c, current in self.find( word, current=current ):
            stem += c
        if complete and current is not None and current.value is current.EMPTY:
            for terminal, c, current in self.complete( current=current ):
                stem += c
        return terminal, stem, current

    def __contains__(self, word: str) -> bool:
        """True iff 'word' has been associated with (or is a unique prefix of) a value in the trie."""
        _, _, result = self.search(word, complete=True)
        return result is not None

    def startswith(self, prefix: str) -> bool:
        """
        Returns if there is any word(s) in the trie that start with the given prefix.
        """
        _, _, result = self.search(prefix)
        return result is not None

    def scan(
        self,
        prefix: str = '',
        current: Optional[TrieNode] = None,
        depth: int = 0,
        predicate: Optional[Callable[[TrieNode], bool]] = None,  # default: terminal
    ) -> Generator[Tuple[str, TrieNode], None, None]:
        """Yields all strings and their TrieNode that match 'prefix' and satisfy 'predicate' (or are
        terminal), in depth-first order.

        Optionally start from the provided 'current' node.

        Any strings that are only prefixes for other string(s) will have node.value == node.EMPTY
        (be non-terminal).

        """
        *_, (terminal, _, current) = self.find(prefix, current=current)
        if current is None:
            return

        satisfied = terminal if predicate is None else predicate( current )
        if satisfied:
            yield prefix, current

        if not depth or depth > 1:
            for char, child in current.children.items():
                for suffix, found in self.scan( current=child, depth=max(0, depth-1), predicate=predicate ):
                    yield prefix + char + suffix, found

    def options(
        self,
        prefix: str = '',
        current: Optional[TrieNode] = None,
    ) -> Generator[Tuple[bool, Set[str]], str, None]:
        """With each symbol provided, yields the next available symbol options.

        Doesn't advance unless a truthy symbol is provided via <generator>send(symbol).

        Completes when the provided symbol doesn't match one of the available options.
        """
        last: str = ''
        *_, (terminal, _, current) = self.find(prefix, current=current) 
        while current is not None:
            terminal = current.value is not current.EMPTY
            symbol: str = yield (terminal, set(current.children))
            if symbol:
                current = current.children.get(symbol)

    def dump_lines(
        self,
        current: Optional[TrieNode] = None,
        indent: int = 6,
        level: int = 0
    ) -> List[str]:
        """Output the Trie and its mapped values in a human-comprehensible form."""
        if current is None:
            current = self.root

        # There can be multiple routes to the same child (ie. glyphs with/without marks)
        kids = defaultdict(set)
        for char, child in current.children.items():
            kids[child].add(char)

        result = []
        if kids and current.value != current.EMPTY:
            # The present node is both a terminal word (eg. "add"), AND has children (eg. "addict", ...)
            result = [ "" ]
        for i, (child, chars) in enumerate(kids.items()):
            first, *rest = self.dump_lines( child, indent=indent, level=level+1 )
            result.append( f"{' ' * (bool(result) or bool(i)) * level * indent}{'/'.join( chars ):{indent}}{first}" )
            result.extend( rest )

        if not result:
            # No kids AND current value == current.EMPTY!  This is a degenerate Trie, but support it.
            result = [""]
        if current.value != current.EMPTY:
            result[0] += f"{' ' * max(0, 10 - level) * indent} == {current.value}"
        return result

    def dump(
        self,
        current: Optional[TrieNode] = None,
        indent: int = 6,
        level: int = 0
    ) -> str:
        return '\n'.join(self.dump_lines( current=current, indent=indent, level=level ))

    def __str__(self):
        return self.dump()


def unmark( word_composed: str ) -> str:
    """This word may contain composite characters with accents like "é" that decompose "e" + "'".

    Most mnemonic encodings require that mnemonic words without accents match the accented word.
    Remove the Mark symbols.

    """
    return ''.join(
        c
        for c in unicodedata.normalize( "NFD", word_composed )
        if not unicodedata.category( c ).startswith('M')
    )


class WordIndices( abc.Mapping ):
    """A Mapping which holds a Sequence of Mnemonic words.

    The underlying Trie is built during construction, but a WordIndices Mapping is not mutable.

    Acts like a basic { "word": index, ... } dict but with additional word flexibility.

    Also behaves like a ["word", "word", ...] list for iteration and indexing.

    Indexable either by int (returning the original canonical word), or by the original word (with
    or without Unicode "Marks") or a unique abbreviations, returning the int index.

    The base mapping is str -> int, and keys()/iter() returns the canonical Mnemonic words.

    The index value for a certain mnemonic word (with our without "Marks") or an abbreviation
    thereof can be obtained:

        <WordIndices>[str(word)]

    The canonical mnemonic word in "NFC" form at a certain index can be obtained via:

        <WordIndices>[int(index)]
        <WordIndices>.keys()[int(index)]

    """
    def __init__(self, sequence: Sequence[str]):
        """Insert a sequence of Unicode words with a value equal to the enumeration, making the
        "unmarked" version an alias of the regular Unicode version.

        """
        self._trie = Trie()
        self._words: List[str] = []
        for i, word in enumerate( sequence ):
            self._words.append( word )
            word_unmarked = unmark( word )

            if word == word_unmarked or len( word ) != len( word_unmarked ):
                # If the word has no marks, or if the unmarked word doesn't have the same number of
                # glyphs, we can't "alias" it; insert the original word with NFC "combined" glyphs.
                self._trie.insert( word, i )
                continue

            # Traverse the TrieNodes representing 'word_unmarked'.  Each glyph in word and
            # word_unmarked is joined by the TrieNode which contains it in .children, and we should
            # never get a None (lose the plot) because we've just inserted 'word'!  This will
            # "alias" each glyph with a mark, to the .children entry for the non-marked glyph.
            self._trie.insert( word_unmarked, i )
            for c, c_un, (_, _, n) in zip( word, word_unmarked, self._trie.find( word_unmarked )):
                assert n is not None
                if c != c_un:
                    if c in n.children and c_un in n.children:
                        assert n.children[c_un] is n.children[c], \
                            f"Attempting to alias {c!r} to {c_un!r} but already exists as a non-alias"
                    n.children[c] = n.children[c_un]

    def __getitem__(self, key: Union[str, int]) -> Union[int, str]:
        """A Mapping from "word" to index, or the reverse.

        Any unique abbreviation with/without UTF-8 "Marks" is accepted.  We keep this return value
        simple, to make WordIndices work similarly to a Dict[str, int] of mnemonic word/index pairs.

        """
        word, index, _ = self.get_details(key)
        return index if isinstance( key, str ) else word

    def get_details(self, key: Union[int, str]) -> Tuple[str, int, Set[str]]:
        """Provide a word (or unique prefix) or an index, and returns a value Tuple consisting of:
            - The canonical word 'str', and
            - The index value, and
            - the set of options available from the end of word, if any

        If no such 'int' index exists, raises IndexError.  If no word(s) are possible starting from
        the given 'str', raises KeyError.

        """
        if isinstance( key, int ):
            # The key'th word (or IndexError)
            return self._words[key], key, set()

        terminal, prefix, node = self._trie.search( key, complete=True )
        if not terminal:
            # We're nowhere in the Trie with this word
            raise KeyError(f"{key!r} does not match any word")
        assert node is not None
        return self._words[node.value], node.value, set(node.children)

    def __len__(self):
        return len( self._words )

    def __iter__(self):
        return iter( self._words )

    def keys(self):
        return self._words

    def values(self):
        return map( self.__getitem__, self._words )

    def items(self):
        return zip( self._words, self.values() )

    def unique(self):
        """All full unique words in the Trie, with/without UTF-8 Marks."""
        for word, _node in self._trie.scan():
            yield word

    def abbreviations(self):
        """All unique abbreviations of words in the Trie, with/without UTF-8 Marks.

        Scans the Trie, identifying each prefix that uniquely abbreviates a word.

        """
        def unique( current ):
            terminal = False
            for terminal, _, complete in self._trie.complete( current ):
                pass
            return terminal

        for abbrev, node in self._trie.scan( predicate=unique ):
            if node.value is node.EMPTY:
                # Only abbreviations (not terminal words) that led to a unique terminal word
                yield abbrev

    def options(self, *args, **kwargs):
        return self._trie.options(*args, **kwargs)

    def __str__(self):
        return str(self._trie)


class IMnemonic(ABC):

    # The specified Mnemonic's details; including the deduced language and all of its word indices
    # for decoding, including valid abbreviations and word with/without the accents.
    _mnemonic: List[str]
    _words: int
    _language: str
    _mnemonic_type: Optional[str]
    _word_indices: Mapping[str, int]

    words_list: List[int]  # The valid mnemonic length(s) available, in words
    languages: List[str]
    wordlist_path: Dict[str, str]

    def __init__(self, mnemonic: Union[str, List[str]], **kwargs) -> None:
        """Initialize an instance of IMnemonic with a mnemonic.

        Converts the provided Mnemonics (abbreviated or missing UTF-8 Marks) to canonical Mnemonic
        words in display-able UTF-8 "NFC" form.

        :param mnemonic: The mnemonic to initialize with, which can be a string or a list of strings.
        :type mnemonic: Union[str, List[str]]
        :param kwargs: Additional keyword arguments.

        :return: No return
        :rtype: NoneType

        """

        mnemonic_list: List[str] = self.normalize(mnemonic)

        # Attempt to unambiguously determine the Mnemonic's language using any preferred 'language'.
        # Raises a MnemonicError if the words are not valid.  Note that the supplied preferred
        # language is only a hint, and the actual language matching the mnemonic will be selected.
        self._word_indices, self._language = self.find_language(mnemonic_list, language=kwargs.get("language"))
        self._mnemonic_type = kwargs.get("mnemonic_type", None)

        # We now know with certainty that the list of Mnemonic words was valid in some language.
        # However, they may have been abbreviations, or had optional UTF-8 Marks removed.  So, use
        # the _word_indices mapping twice, from str (matching word/abbrev) -> int (index) -> str
        # (canonical word from keys).  This will work with a find_languages that returns either a
        # WordIndices Mapping or a simple dict word->index Mapping (but abbreviations or missing
        # Marks will not be supported)
        canonical_words = list(self._word_indices)
        self._mnemonic: List[str] = [
            canonical_words[self._word_indices[word]]
            for word in mnemonic_list
        ]
        self._words = len(self._mnemonic)

        # We have the canonical Mnemonic words.  Decode them for validation, thus preserving the
        # real MnemonicError details if the words do not form a valid Mnemonic.
        self.decode(self._mnemonic, **kwargs)

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

        raise NotImplementedError

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
        cls, language: str, wordlist_path: Optional[Dict[str, Union[str, List[str]]]] = None
    ) -> List[str]:
        """Retrieves the standardized (NFC normalized, lower-cased) word list for the specified language.

        Uses NFC normalization for internal processing consistency. BIP-39 wordlists are generally
        stored in NFD format (with some exceptions like russian) but we normalize to NFC (for
        internal word comparisons and lookups, and for display.

        We do not want to use 'normalize' to do this, because normalization of Mnemonics may have
        additional functionality beyond just ensuring symbol and case standardization.

        Supports wordlist_path mapping language to either a path:

            {'language': '/some/path'},

        or to the language's actual words_list data:

            {'language': ['words', 'list', ...]}

        Ignores blank lines and # ... comments

        :param language: The language for which to get the word list.
        :type language: str
        :param wordlist_path: Optional dictionary mapping language names to file paths of their word lists, or the words list.
        :type wordlist_path: Optional[Dict[str, Tuple[str, List[str]]]

        :return: A list of words for the specified language, normalized to NFC form.
        :rtype: List[str]

        """

        wordlist_path = cls.wordlist_path if wordlist_path is None else wordlist_path

        # May provide a filesystem path str, or a List-like sequence of words
        if isinstance( wordlist_path[language], str ):
            with open(os.path.join(os.path.dirname(__file__), wordlist_path[language]), "r", encoding="utf-8") as fin:
                words_list_raw: List[str] = list( fin )
        else:
            words_list_raw: List[str] = list( wordlist_path[language] )

        # Ensure any words are provided in either NFKC or NFKD form.  This eliminates words lists
        # where the provided word is not in standard NFC or NFD form, down-cases them and removes
        # any leading/trailing whitespace, then ignores empty lines or full-line comments (trailing
        # comments are not supported).
        words_list: List[str] = []
        for word in map( str.lower, map( str.strip, words_list_raw )):
            if not word or word.startswith("#"):
                continue
            word_nfc = unicodedata.normalize("NFKC", word)
            word_nfkd = unicodedata.normalize( "NFKD", word_nfc)
            assert word == word_nfkd or word == word_nfc, \
                f"Original {language} word {word!r} failed to round-trip through NFC: {word_nfc!r} / NFKD: {word_nfkd!r}"
            words_list.append(word_nfc)

        return words_list

    @classmethod
    @lru_cache(maxsize=32)
    def _get_cached_word_indices(cls, wordlist_tuple: tuple[str]) -> WordIndices:
        """Create and cache WordIndices for a given language and wordlist.

        :param language: The language name for identification
        :type language: str
        :param wordlist_tuple: Tuple of words (hashable for caching)
        :type wordlist_tuple: tuple

        :return: Cached WordIndices object
        :rtype: WordIndices
        """
        return WordIndices(wordlist_tuple)

    @classmethod
    def wordlist_indices(
        cls, wordlist_path: Optional[Dict[str, Union[str, List[str]]]] = None, language: Optional[str] = None,
    ) -> Tuple[str, List[str], WordIndices]:
        """Yields each 'candidate' language, its NFKC-normalized words List, and its WordIndices

        Optionally restricts to the preferred language, if available.

        The WordIndices Mapping supporting indexing by 'int' word index, or 'str' with optional
        accents and all unique abbreviations.

        """
        for candidate in (wordlist_path.keys() if wordlist_path else cls.languages):
            if language and candidate != language:
                continue
            # Normalized NFC, so characters and accents are combined
            words_list: List[str] = cls.get_words_list_by_language(
                language=candidate, wordlist_path=wordlist_path
            )
            # Convert to tuple for hashing, cache the WordIndices creation
            word_indices = cls._get_cached_word_indices(tuple(words_list))
            yield candidate, words_list, word_indices

    @classmethod
    def find_language(
        cls,
        mnemonic: List[str],
        wordlist_path: Optional[Dict[str, Union[str, List[str]]]] = None,
        language: Optional[str] = None,
    ) -> Tuple[Mapping[str, int], str]:
        """Finds the language of the given mnemonic by checking against available word list(s),
        preferring the specified 'language' if supplied and exactly matches an available language.
        If a 'wordlist_path' dict of {language: path} is supplied, its languages are used.  If a
        'language' (optional) is supplied, any ambiguity is resolved by selecting the preferred
        language, if available and the mnemonic matches.  If not, the least ambiguous language found
        is selected.

        If an abbreviation match is found, then the language with the largest total number of
        symbols matched (least ambiguity) is considered best.  This handles the (rare) case where a
        mnemonic is valid in multiple languages, either directly or as an abbreviation (or
        completely valid in both languages):

          english: abandon about   badge machine minute ozone salon science ...
          french:  abandon aboutir badge machine minute ozone salon science ...

        Clearly, it is /possible/ to specify a Mnemonic which for which it is impossible to uniquely
        determine the language!  However, this Mnemonic would probably be encoding very poor
        entropy, so is quite unlikely to occur in a Mnemonic storing true entropy.  But, it is
        certainly possible (see above).  However, especially with abbreviations, it is possible for
        this to occur.  For these Mnemonics, it is /impossible/ to know (or guess) which language
        the Mnemonic was intended to be {en,de}coded with.  Since an incorrect "guess" would lead to
        a different seed and therefore different derived wallets -- a match to multiple languages
        with the same quality and with no preferred 'language' leads to an Exception.

        Even the final word (which encodes some checksum bits) cannot determine the language with
        finality, because it is only a statistical checksum!  For 128-bit 12-word encodings, only 4
        bits of checksum are represented.  Therefore, there is a 1/16 chance that any entropy that
        encodes to words in both languages will *also* have the same 4 bits of checksum!  24-word
        BIP-39 Mnemonics only encode 8 bits of checksum, so 1/256 of random entropy that encodes to
        words common to both languages will pass the checksum test.

        Therefore, specifying a 'language' is necessary to eliminate the possibility of erroneously
        recognizing the wrong language for some Mnemonic, and therefore producing the wrong derived
        cryptographic keys.


        The returned Mapping[str, int] contains all accepted word -> index mappings, including all
        acceptable abbreviations, with and without character accents.  This is typically the
        expected behavior for most Mnemonic encodings ('café' == 'cafe' for Mnemonic word matching).

        :param mnemonic: The mnemonic to check, represented as a list of words.
        :type mnemonic: List[str]
        :param wordlist_path: Optional dictionary mapping language names to file paths of their word lists, or the word list.
        :type wordlist_path: Optional[Dict[str, Union[str, List[str]]]]
        :param language: The preferred language, used if valid and mnemonic matches.
        :type mnemonic: Optional[str]

        :return: A tuple containing the language's word indices and the language name.
        :rtype: Tuple[[str, int], str]

        """

        language_indices: Dict[str, Mapping[str, int]] = {}
        quality: Dict[str, int] = defaultdict(int)  # How many language symbols were matched
        for candidate, words_list, words_indices in cls.wordlist_indices( wordlist_path=wordlist_path ):
            language_indices[candidate] = words_indices
            try:
                # Check for exact matches and unique abbreviations, ensuring comparison occurs in
                # composite "NFKC" normalized characters.
                for word in mnemonic:
                    word_composed = unicodedata.normalize( "NFKC", word )
                    try:
                        index = words_indices[word_composed]
                    except KeyError as ex:
                        if candidate in quality:
                            quality.pop(candidate)
                        raise MnemonicError(f"Unable to find word {word} in {candidate}") from ex
                    word_canonical = words_indices.keys()[index]
                    quality[candidate] += len( word_canonical )

                if candidate == language:
                    # All words exactly matched word with or without accents, complete or uniquely
                    # abbreviated words in the preferred language!  We're done - we don't need to
                    # test further candidate languages.
                    return words_indices, candidate

                # All words exactly matched words in this candidate language, or some words were
                # found to be unique abbreviations of words in the candidate, but it isn't the
                # preferred language (or no preferred language was specified).  Keep track of its
                # quality of match, but carry on testing other candidate languages.
            except (MnemonicError, ValueError):
                continue

        # No unambiguous match to any preferred language found (or no language matched all words).
        if not quality:
            raise MnemonicError(f"Invalid {cls.name()} mnemonic words")

        # Select the best available.  Sort by the number of characters matched (more is better -
        # less ambiguous).  This is a statistical method; it is still dangerous, and we should fail
        # instead of returning a bad guess!
        (candidate, matches), *worse = sorted(quality.items(), key=lambda k_v: k_v[1], reverse=True )
        if worse and matches == worse[0][1]:
            # There are more than one matching candidate languages -- and they are both equivalent
            # in quality.  We cannot know (or guess) the language with any certainty.
            raise MnemonicError(f"Ambiguous languages {', '.join(c for c, w in worse)} or {candidate} for mnemonic; specify a preferred language")

        return language_indices[candidate], candidate

    @classmethod
    def collect(
        cls,
        languages: Optional[Collection[str]] = None,
        wordlist_path: Optional[Dict[str, Union[str, List[str]]]] = None,
    ) -> Generator[Tuple[Set[str], bool, Set[str]], str, None]:
        """A generator taking input symbols, and producing a sequence of sets of possible next
        characters in all remaining languages.

        With each symbol provided, yields the remaining candidate languages, whether the symbol
        indicated a terminal word in some language, and the available next symbols in all remaining
        languages.

        """
        candidates: Dict[str, WordIndices] = dict(
            (candidate, words_indices)
            for candidate, _, words_indices in cls.wordlist_indices( wordlist_path=wordlist_path )
            if languages is None or candidate in languages
        )

        word: str = ''
        updaters = {
            candidate: words_indices.options()
            for candidate, words_indices in candidates.items()
        }

        symbol = None
        complete = set()
        while complete < set(updaters):
            terminal = False
            possible = set()
            for candidate, updater in updaters.items():
                try:
                    done, available = updater.send(symbol)
                except StopIteration:
                    complete.add( candidate )
                terminal |= done
                possible |= available
            symbol = yield (set(updaters) - complete, terminal, possible)

    @classmethod
    def is_valid(cls, mnemonic: Union[str, List[str]], language: Optional[str] = None, **kwargs) -> bool:
        """Checks if the given mnemonic is valid.

        Catches mnemonic-validity related or word indexing Exceptions and returns False, but lets
        others through; asserts, hdwallet.exceptions.Error, general programming errors, etc.

        :param mnemonic: The mnemonic to check.
        :type mnemonic: str
        :param language: The preferred language of the mnemonic.
        :type mnemonic: str
        :param kwargs: Additional keyword arguments.

        :return: True if the strength is valid, False otherwise.
        :rtype: bool

        """

        try:
            cls.decode(mnemonic=mnemonic, language=language, **kwargs)
            return True
        except (ValueError, KeyError, MnemonicError, ChecksumError):
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
        Checks if the given number of words is valid.

        :param words: The number of words to check.
        :type words: int

        :return: True if the number of mnemonic words is valid, False otherwise.
        :rtype: bool
        """

        return words in cls.words_list

    @classmethod
    def normalize(cls, mnemonic: Union[str, List[str]]) -> List[str]:
        """Normalizes the given mnemonic by splitting it into a list of words if it is a string.
        Resilient to extra whitespace, compatibility characters such as full-width symbols,
        decomposed characters and accents, and down-cases uppercase symbols using NFKC
        normalization.

        This does not canonicalize the Mnemonic, because we do not know the language, nor can we
        reliably deduce it without a preferred language (since Mnemonics may be valid in multiple
        languages).

        Recognizes hex strings (raw entropy), and attempts to normalize them as appropriate for the
        IMnemonic-derived class using 'from_entropy'.  Thus, all IMnemonics can accept either
        mnemonic strings or raw hex-encoded entropy, if they use the IMnemonic.normalize base
        method in their derived 'decode' and 'is_valid' implementations.

        This makes sense for most Mnemonics, which produce an repeatable encoding for the same entropy;
        Mnemonics that produce different encodings will need alternative implementations.  They should
        handle raw entropy directly.

        :param mnemonic: The mnemonic value, which can be a single string of words or a list of words.
        :type mnemonic: Union[str, List[str]]

        :return: A list of words from the mnemonic, normalized for internal processing.
        :rtype: List[str]

        """
        if isinstance(mnemonic, str):
            if ( len(mnemonic.strip()) * 4 in cls.words_to_entropy_strength.values()
                 and all(c in string.hexdigits for c in mnemonic.strip())):
                mnemonic: str = cls.from_entropy(mnemonic, language=cls.languages[0])
            mnemonic: List[str] = mnemonic.strip().split()
        return list(unicodedata.normalize("NFKC", word.lower()) for word in mnemonic)
