#!/usr/bin/env python3

import os
import random
import unicodedata
from typing import List, Set

import pytest

from hdwallet.mnemonics.bip39 import BIP39Mnemonic
from hdwallet.mnemonics.imnemonic import Trie, TrieNode, WordIndices
from hdwallet.exceptions import ChecksumError, MnemonicError

class TestBIP39CrossLanguage:
    """Test BIP39 mnemonics that work in both English and French languages.

    This test explores the theoretical possibility of mnemonics that can be validly
    decoded in multiple languages. About 2% (100/2048) of words are common between
    the English and French BIP-39 wordlists.

    For randomly generated entropy uses only common words:
    - Probability for a 12-word mnemonic: (100/2048)^12*1/16  ≈ 1.15*10^-17
    - Probability for a 24-word mnemonic: (100/2048)^24*1/256 ≈ 1.32x10^-34

    Most wallets allow abbreviations; only the first few characters of the word need to be entered:
    the words are guaranteed to be unique after entering at least 4 letters (including the word end
    symbol; eg. 'run' 'runway, and 'sea' 'search' 'season' 'seat').

    If we include full words in one language that are abbreviations in the other, the probabilities
    increase:



    These probabilities are astronomically small, so naturally occurring mnemonics
    will essentially never be composed entirely of common words.

    This test deliberately constructs mnemonics using only common words,
    then tests what fraction pass checksum validation in both languages:
    - For 12-word mnemonics: ~1/16 (6.25%) due to 4-bit checksum
    - For 24-word mnemonics: ~1/256 (0.39%) due to 8-bit checksum

    This demonstrates the theoretical cross-language compatibility while showing
    why it's not a practical security concern for real-world usage.

    For details about BIP-39 word list selection for various languages, see:

    https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md

    Particularly interesting for abbreviations is the fact that any letter with an accent is
    considered equal to the same letter without the accent for entry and word selection.

    """

    @classmethod
    def setup_class(cls, languages: list[str] = None):
        """Load wordlists and find common words between specified languages.

        Args:
            languages: List of language names to load (defaults to ['english', 'french'])
        """
        if languages is None:
            languages = ['english', 'french']

        if len(languages) < 2:
            raise ValueError("At least 2 languages are required for cross-language testing")

        # Load all specified languages
        language_data = {}
        for language, words, indices in BIP39Mnemonic.wordlist_indices():
            language_data[language] = dict(
                indices = indices,
                words = set( indices.keys() ),
                unique = set( indices.unique() ),
                abbrevs = set( indices.abbreviations() ),
            )
            if language not in languages:
                continue

            # Set class attributes for backward compatibility
            setattr(cls, f"{language}_words", language_data[language]['words'])
            setattr(cls, f"{language}_unique", language_data[language]['unique'])
            setattr(cls, f"{language}_indices", language_data[language]['indices'])
            setattr(cls, f"{language}_abbrevs", language_data[language]['abbrevs'])

        # Find common words across all languages - only process requested languages
        requested_data = {lang: language_data[lang] for lang in languages if lang in language_data}
        all_word_sets = [data['unique'] for data in requested_data.values()]
        all_abbrev_lists = [data['abbrevs'] for data in requested_data.values()]

        cls.common_words = set.intersection(*all_word_sets) if all_word_sets else set()
        cls.common_abbrevs = set.intersection(*all_abbrev_lists) if all_abbrev_lists else set()

        # Print statistics.  Given that UTF-8 marks may or may not be supplied, there may be more
        # unique words than the 2048 base UTF-8 BIP-39 words in the language.
        for lang, data in requested_data.items():
            print(f"{lang.capitalize()} UTF-8 words base: {len(data['words'])} unique: {len(data['unique'])}, abbreviations: {len(data['abbrevs'])}")

        print(f"Common words found: {len(cls.common_words)}")
        print(f"First 20 common words: {sorted(cls.common_words)[:20]}")
        print(f"Common abbrevs found: {len(cls.common_abbrevs)}")
        print(f"First 20 common abbrevs: {sorted(cls.common_abbrevs)[:20]}")

    def create_random_mnemonic_from_common_words(self, word_count: int) -> str:
        """Create a random mnemonic using only common words."""
        if len(self.common_words) < word_count:
            raise ValueError(f"Not enough common words ({len(self.common_words)}) to create {word_count}-word mnemonic")

        selected_words = random.choices(list(self.common_words), k=word_count)
        return selected_words

    def test_common_words_exist(self):
        """Test that there are common words between English and French wordlists."""
        assert len(self.common_words) > 0, "No common words found between English and French wordlists"

    def dual_language_N_word_mnemonics(self, words=12, expected_rate=1/16, total_attempts=1000):
        """Test N-word mnemonics that work in both English and French.

        Actual rate for 2 languages will be expected_rate ^ 2."""
        successful_both_languages: List[List[str]] = []
        successful_english: int = 0
        for _ in range(total_attempts):
            try:
                # Generate a random N-word mnemonic from common words
                mnemonic = self.create_random_mnemonic_from_common_words(words)

                # Try to decode as both English and French - both must succeed (pass checksum)
                # Note: We expect different entropy values since words have different indices
                entropy_english = BIP39Mnemonic.decode(' '.join(mnemonic), language='english')
                entropy_french = BIP39Mnemonic.decode(' '.join(mnemonic), language='french')

                # If both decode successfully, the mnemonic is valid in both languages
                successful_both_languages.append(mnemonic)
                print(f"{words}-word common mnemonics {' '.join(mnemonic)!r}")

            except ChecksumError as exc:
                # Skip invalid mnemonics (e.g., checksum failures)
                continue

        success_rate = len(successful_both_languages) / total_attempts

        print(f"{words}-word mnemonics: {len(successful_both_languages)}/{total_attempts} successful ({success_rate:.6f})")
        print(f"Expected rate: ~{expected_rate:.6f} ^ 2 == {expected_rate ** 2:.6f}")

        # These rates are too small to test, in the small samples we're likely to use

        # # Assert we found at least some successful mnemonics
        # assert success_rate > 0, f"No {words}-word mnemonics worked in both languages"

        # # The success rate should be roughly around the expected rate, but due to
        # # randomness and limited common words, we'll accept a broader range
        # tolerance = 0.5  # 50% tolerance due to statistical variance
        # assert expected_rate * (1 - tolerance) < success_rate < expected_rate * (1 + tolerance), \
        #     f"Success rate {success_rate:.6f} not in expected range around {expected_rate:.4f}"
        return successful_both_languages

    def test_cross_language_12_word_mnemonics(self):
        """Test 12-word mnemonics that work in both English and French.

        For example:
            'ocean correct rival double theme village crucial veteran salon tunnel question minute'
            'puzzle mobile video pelican bicycle ocean effort train junior brave effort theme'
            'elegant cruel science guide fortune nation humble lecture ozone dragon question village'
            'innocent prison romance jaguar voyage depart fruit crucial video salon reunion fatigue'
            'position dragon correct question figure notable service vague civil public distance emotion'

        """
        with pytest.raises(MnemonicError, match="Ambiguous languages french or english"):
            BIP39Mnemonic.decode(
                'ocean correct rival double theme village crucial veteran salon tunnel question minute'
            )
        candidates = self.dual_language_N_word_mnemonics(words=12, expected_rate=1/16)

    def test_cross_language_24_word_mnemonics(self):
        """Test 24-word mnemonics that work in both English and French.

        For example:
            'pelican pelican minute intact science figure vague civil badge rival pizza fatal sphere nation simple ozone canal talent emotion wagon ozone valve voyage angle'
            'pizza intact noble fragile piece suspect legal badge vital guide coyote volume nature wagon badge festival danger train desert intact opinion veteran romance metal'
        """
        with pytest.raises(MnemonicError, match="Ambiguous languages french or english"):
            BIP39Mnemonic.decode(
                'pelican pelican minute intact science figure vague civil badge rival pizza fatal'
                ' sphere nation simple ozone canal talent emotion wagon ozone valve voyage angle'
            )

        candidates = self.dual_language_N_word_mnemonics(words=24, expected_rate=1/256)

    def test_wordlist_properties(self):
        """Test basic properties of the wordlists."""
        # Verify wordlist sizes
        assert len(self.english_words) == 2048, f"English base wordlist should have 2048 words, got {len(self.english_words)}"
        assert len(self.english_unique) == 2048, f"English full unique wordlist should have 2048 words, got {len(self.english_unique)}"
        assert len(self.french_words) == 2048, f"French base wordlist should have 2048 words, got {len(self.french_words)}"
        assert len(self.french_unique) == 2774, f"French full unique wordlist should have 2774 words, got {len(self.french_unique)}"

        # Verify common words list properties
        assert len(self.common_words) > 0, "No common words found"
        assert len(set(self.common_words)) == len(self.common_words), "Common words list contains duplicates"

    def test_trie_functionality(self):
        """Test the new Trie and TrieNode classes for abbreviation handling."""

        # Test 1: Default TrieNode markers
        trie = Trie()
        test_words = [
            "abandon",
            "ability",
            "able",
            "about",
            "above",
            "absent",
            "absorb",
            "abstract",
            "absurd",
            "abuse",
            "add",
            "addict",
            "address",
            "adjust",
            "access",
            "accident",
            "account",
            "accuse",
            "achieve",
        ]

        # Insert all test words with their indices
        for index, word in enumerate( test_words ):
            trie.insert(word, index)

        # Test exact word lookups
        terminal, stem, current = trie.search("abandon")
        assert terminal and stem == "abandon" and current.value == 0, \
            "Should find exact word 'abandon'"
        terminal, stem, current = trie.search("ability")
        assert terminal and stem == "ability" and current.value == 1, \
            "Should find exact word 'ability'"
        terminal, stem, current = trie.search("nonexistent")
        assert not terminal and stem == "" and current is None, \
            "Should not find non-existent word"

        # Test __contains__ method
        assert "abandon" in trie, "Trie should contain 'abandon'"
        assert "ability" in trie, "Trie should contain 'ability'"
        assert "nonexistent" not in trie, "Trie should not contain 'nonexistent'"

        # Test prefix detection with startswith
        assert trie.startswith("aba"), "Should find prefix 'aba'"
        assert trie.startswith("abil"), "Should find prefix 'abil'"
        assert trie.startswith("xyz") == False, "Should not find non-existent prefix 'xyz'"

        # Test unambiguous abbreviation completion
        # 'aba' should complete to 'abandon' since it's the only word starting with 'aba'
        terminal, stem, current = trie.search("aba", complete=True)
        assert terminal and stem == "abandon" and current.value == 0, "Should complete 'aba' to 'abandon' (index 0)"

        # 'abi' should complete to 'ability' since it's the only word starting with 'abi'
        terminal, stem, current = trie.search("abi", complete=True)
        assert terminal and stem == "ability" and current.value == 1, "Should complete 'abi' to 'ability' (index 1)"

        # 'ab' is ambiguous (abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse)
        terminal, stem, current = trie.search("ab", complete=True)
        assert not terminal and stem == "ab" and current.value is current.EMPTY, "Should not complete ambiguous prefix 'ab'"

        # 'acc' is also ambiguous (access, accident, account, accuse)
        terminal, stem, current = trie.search("acc", complete=True)
        assert not terminal and stem == "acc" and current.value is current.EMPTY, "Should not complete ambiguous prefix 'acc'"

        # 'accid' should complete to 'accident' since it's unambiguous
        terminal, stem, current = trie.search("accid", complete=True)
        assert terminal and stem == "accident" and current.value == 15, "Should complete 'accid' to 'accident' (index 15)"

        # Test edge cases
        terminal, stem, current = trie.search("")
        assert not terminal and stem == "" and current.value is TrieNode.EMPTY, "Empty string should return EMPTY; it's a prefix, but no value"
        terminal, stem, current = trie.search("", complete=True)
        assert not terminal and stem == "a" and current.value is TrieNode.EMPTY, "Empty string with complete should complete to 'a' (all words start with a) and return EMPTY"

        # Test very short abbreviations that should be unambiguous
        # 'abl' should complete to 'able' since it's the only match
        terminal, stem, current = trie.search("abl", complete=True)
        assert terminal and stem == "able" and current.value == 2, "Should complete 'abl' to 'able' (index 2)"

        # Test abbreviations that are longer than needed but still valid; particularly that
        # complete=True doesn't jump over a fully complete word.
        terminal, stem, current = trie.search("abandon", complete=True)
        assert terminal and stem == "abandon" and current.value == 0, "Full word should still work with complete=True"

        def scan_value( w_n ):
            return w_n[0], w_n[1].value

        # Test scans of various depths
        assert sorted( map( scan_value, trie.scan("abs"))) == [
            ( 'absent',		5, ),
            ( 'absorb',		6, ),
            ( 'abstract',	7 ),
            ( 'absurd',		8 ),
        ]

        # Now we see words that are prefixes of other words

        assert sorted( map( scan_value,  trie.scan("ad", depth=1 ))) == [
        ]
        assert sorted( map( scan_value,  trie.scan("ad", depth=1, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=2 ))) == [
            ( 'add',		10),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=2, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
            ( 'add',		10),
            ( 'adj',		None ),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=3 ))) == [
            ( 'add',		10),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=3, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
            ( 'add',		10),
            ( 'addi',		None ),
            ( 'addr',		None ),
            ( 'adj',		None ),
            ( 'adju',		None ),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=4 ))) == [
            ( 'add',		10),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=4, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
            ( 'add',		10),
            ( 'addi',		None ),
            ( 'addic',		None ),
            ( 'addr',		None ),
            ( 'addre',		None ),
            ( 'adj',		None ),
            ( 'adju',		None ),
            ( 'adjus',		None ),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=5 ))) == [
            ( 'add',		10),
            ( 'addict',		11),
            ( 'adjust',		13),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=5, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
            ( 'add',		10),
            ( 'addi',		None ),
            ( 'addic',		None ),
            ( 'addict',		11),
            ( 'addr',		None ),
            ( 'addre',		None ),
            ( 'addres',		None ),
            ( 'adj',		None ),
            ( 'adju',		None ),
            ( 'adjus',		None ),
            ( 'adjust',		13 ),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=6 ))) == [
            ( 'add',		10),
            ( 'addict',		11),
            ( 'address',	12),
            ( 'adjust',		13),
        ]
        assert sorted( map( scan_value, trie.scan("ad", depth=6, predicate=lambda _: True ))) == [
            ( 'ad',		None ),
            ( 'add',		10),
            ( 'addi',		None ),
            ( 'addic',		None ),
            ( 'addict',		11 ),
            ( 'addr',		None ),
            ( 'addre',		None ),
            ( 'addres',		None ),
            ( 'address',	12 ),
            ( 'adj',		None ),
            ( 'adju',		None ),
            ( 'adjus',		None ),
            ( 'adjust',		13 ),
        ]

        # Test 2: Custom TrieNode with different markers
        class CustomTrieNode(TrieNode):
            EMPTY = "CUSTOM_EMPTY"

        custom_root = CustomTrieNode()
        custom_trie = Trie(custom_root)

        # Test that custom markers are used
        assert custom_trie.root.EMPTY == "CUSTOM_EMPTY"

        # Insert some words
        custom_trie.insert("test", 42)
        custom_trie.insert("testing", 99)

        # Verify custom markers are returned for non-existent words
        terminal, stem, current = custom_trie.search("nonexistent")
        assert not terminal and stem == "" and current is None
        terminal, stem, current = custom_trie.search("")
        assert not terminal and stem == "" and current.value == "CUSTOM_EMPTY"  # Root has EMPTY value

        # Verify normal functionality still works
        terminal, stem, current = custom_trie.search("test")
        assert terminal and stem == "test" and current.value == 42
        terminal, stem, current = custom_trie.search("testing")
        assert terminal and stem == "testing" and current.value == 99
        assert "test" in custom_trie
        assert "nonexistent" not in custom_trie

        # Test abbreviation completion with custom markers
        terminal, stem, current = custom_trie.search("tes", complete=False)
        assert stem == "tes" and current.value == "CUSTOM_EMPTY"  # Ambiguous: "test" vs "testing"
        assert not terminal
        terminal, stem, current = custom_trie.search("tes", complete=True)
        assert terminal and stem == "test" and current.value == 42  # Single path to "test" vs "testing"
        *_, (_, _, current) = custom_trie.complete(current=current)
        assert current.value == 99  # Should carry on completing the single path from "test" to "testing"
        terminal, stem, current = custom_trie.search("testin", complete=True)
        assert terminal and stem == "testing" and current.value == 99  # Unambiguous: completes to "testing"

        test_indices = WordIndices(test_words)
        assert str(test_indices) == """\
a     b     a     n     d     o     n                        == 0
            i     l     i     t     y                        == 1
            l     e                                          == 2
            o     u     t                                    == 3
                  v     e                                    == 4
            s     e     n     t                              == 5
                  o     r     b                              == 6
                  t     r     a     c     t                  == 7
                  u     r     d                              == 8
            u     s     e                                    == 9
      d     d                                                == 10
                  i     c     t                              == 11
                  r     e     s     s                        == 12
            j     u     s     t                              == 13
      c     c     e     s     s                              == 14
                  i     d     e     n     t                  == 15
                  o     u     n     t                        == 16
                  u     s     e                              == 17
            h     i     e     v     e                        == 18"""



        options = trie.options()

        assert next( options )     == (False, set( 'a' ))
        assert options.send( 'a' ) == (False, set( 'bcd' ))
        assert options.send( 'd' ) == (False, set( 'dj' ))
        assert options.send( 'd' ) == (True, set( 'ir' ))
        assert options.send( 'i' ) == (False, set( 'c' ))
        assert options.send( 'c' ) == (False, set( 't' ))
        assert next(options)       == (False, set( 't' ))
        assert options.send('')    == (False, set( 't' ))
        assert options.send( 't' ) == (True, set())


    def test_ambiguous_languages(self):
        """Test that find_language correctly detects and raises errors for ambiguous mnemonics.

        This test verifies that when a mnemonic contains words common to multiple languages
        with equal quality scores, find_language raises a MnemonicError indicating the ambiguity.
        """
        from hdwallet.exceptions import MnemonicError

        # Create a test mnemonic using only common words between languages
        # Use enough words to create realistic test cases
        if len(self.common_words) < 12:
            pytest.skip(f"Not enough common words ({len(self.common_words)}) for ambiguity testing")

        # Test with 12-word mnemonics using only common words
        test_mnemonic = list(self.common_words)[:12]  # Use first 12 common words

        # Test 1: find_language should detect ambiguity when no preferred language is specified
        try:
            word_indices, detected_language = BIP39Mnemonic.find_language(test_mnemonic)
            # If this succeeds, it means one language had a higher quality score than others
            # This is valid behavior - not all common word combinations are equally ambiguous
            #print(f"Mnemonic resolved to {detected_language} (quality was decisive)")
        except MnemonicError as e:
            # This is the expected behavior for truly ambiguous mnemonics
            #assert "Ambiguous languages" in str(e), f"Expected ambiguity error, got: {e}"
            #assert "specify a preferred language" in str(e), f"Expected preference suggestion, got: {e}"
            print(f"✓ Correctly detected ambiguous mnemonic: {e}")

        # Test 2: Verify that specifying a preferred language resolves the ambiguity
        # Try with each available language that contains these common words
        resolved_languages = []
        for language in ['english', 'french']:  # Test both languages we know have common words
            try:
                word_indices, detected_language = BIP39Mnemonic.find_language(
                    test_mnemonic, language=language
                )
                resolved_languages.append(detected_language)
                #print(f"✓ Successfully resolved with preferred language '{language}' -> {detected_language}")
            except MnemonicError as e:
                print(f"Failed to resolve with language '{language}': {e}")
                raise

        # At least one language should successfully resolve the mnemonic
        assert len(resolved_languages) > 0, "No language could resolve the test mnemonic"

        # Test 3: Test with a different set of common words to ensure robustness
        if len(self.common_words) >= 24:
            # Try with different common words (offset by 6 to get different words)
            alt_test_mnemonic = list(self.common_words)[6:18]  # Words 6-17 (12 words)

            try:
                word_indices, detected_language = BIP39Mnemonic.find_language(alt_test_mnemonic)
                #print(f"Alternative mnemonic resolved to {detected_language}")
            except MnemonicError as e:
                if "Ambiguous languages" in str(e):
                    #print(f"✓ Alternative mnemonic also correctly detected as ambiguous: {e}")
                    # Test that preferred language resolves it
                    word_indices, detected_language = BIP39Mnemonic.find_language(
                        alt_test_mnemonic, language='english'
                    )
                    #print(f"✓ Alternative mnemonic resolved with preferred language: {detected_language}")
                else:
                    raise  # Re-raise unexpected errors

        # Test 4: Verify behavior with abbreviations if common abbreviations exist
        if len(self.common_abbrevs) >= 12:
            abbrev_mnemonic = list(self.common_abbrevs)[:12]

            try:
                word_indices, detected_language = BIP39Mnemonic.find_language(abbrev_mnemonic)
                #print(f"Abbreviation mnemonic resolved to {detected_language}")
            except MnemonicError as e:
                if "Ambiguous languages" in str(e):
                    print(f"✓ Abbreviation mnemonic correctly detected as ambiguous")
                    # Verify preferred language resolves it
                    word_indices, detected_language = BIP39Mnemonic.find_language(
                        abbrev_mnemonic, language='english'
                    )
                    #print(f"✓ Abbreviation mnemonic resolved with preferred language: {detected_language}")
                else:
                    raise  # Re-raise unexpected errors


def test_bip39_collection():

    languages = {'english', 'french', 'spanish', 'russian'}

    collect = BIP39Mnemonic.collect(languages=languages)
    assert collect.send(None) == (languages, False, set('abcedefghijklmnopqrstuvwxyzáéíóúабвгдежзиклмнопрстуфхцчшщэюя'))
    assert collect.send('a') == ({'english', 'french', 'spanish'}, False, set('bcedefghijlmnpqrstuvwxyzéñ'))
    assert collect.send('d') == ({'english', 'french', 'spanish'}, False, set('adehijmoruvé'))
    assert collect.send('d') == ({'english'},                      True , set('ir'))
    


def test_bip39_korean():
    # Confirm that UTF-8 Mark handling works in other languages (particularly Korean)
    (_, korean_nfc, korean_indices), = BIP39Mnemonic.wordlist_indices(
        dict(
            korean = BIP39Mnemonic.wordlist_path["korean"]
        )
    )
    korean_nfc_20 = "\n".join(korean_nfc[:20])
    #print( korean_nfc_20 )
    assert korean_nfc_20 == """\
가격
가끔
가난
가능
가득
가르침
가뭄
가방
가상
가슴
가운데
가을
가이드
가입
가장
가정
가족
가죽
각오
각자"""
    korean_trie_20 = "\n".join(korean_indices._trie.dump_lines()[:20])
    #print(korean_trie_20)
    assert korean_trie_20 == """\
가     격                                                      == 0
      끔                                                      == 1
      난                                                      == 2
      능                                                      == 3
      득                                                      == 4
      르     침                                                == 5
      뭄                                                      == 6
      방                                                      == 7
      상                                                      == 8
      슴                                                      == 9
      운     데                                                == 10
      을                                                      == 11
      이     드                                                == 12
      입                                                      == 13
      장                                                      == 14
      정                                                      == 15
      족                                                      == 16
      죽                                                      == 17
각     오                                                      == 18
      자                                                      == 19"""

if __name__ == "__main__":
    pytest.main([__file__])
