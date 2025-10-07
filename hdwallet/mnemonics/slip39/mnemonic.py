#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import re
from typing import (
    Union, Dict, Iterable, List, Optional, Sequence, Collection, Tuple
)

from ...entropies import (
    ENTROPIES, IEntropy, SLIP39Entropy, SLIP39_ENTROPY_STRENGTHS
)
from ...exceptions import (
    EntropyError, MnemonicError
)
from ...utils import (
    get_bytes,
    bytes_to_string,
)
from ..imnemonic import IMnemonic

from shamir_mnemonic import generate_mnemonics
from shamir_mnemonic.constants import MAX_SHARE_COUNT
from shamir_mnemonic.recovery import RecoveryState, Share

from tabulate import tabulate


class SLIP39_MNEMONIC_WORDS:

    TWENTY: int = 20
    THIRTY_THREE: int = 33
    FIFTY_NINE: int = 59


class SLIP39_MNEMONIC_LANGUAGES:

    ENGLISH: str = "english"


def group_parser( group_spec, size_default: Optional[int] = None) -> Tuple[str, Tuple[int, int]]:
    """Parse a SLIP-39 group specification; a name up to the first digit, ( or /, then a
    threshold/count spec:

        Frens6, Frens 6, Frens(6)	- A 3/6 group (default is 1/2 of group size, rounded up)
        Frens2/6, Frens(2/6)		- A 2/6 group

    Prevents 1/N groups (use 1/1, and duplicate the mnemonic to the N participants).

    All aspects of a group specification are optional; an empty spec yields a default group.

    """
    g_match			= group_parser.RE.match( group_spec )
    if not g_match:
        raise ValueError( f"Invalid group specification: {group_spec!r}" )
    name			= g_match.group( 'name' ) or ""
    if name:
        name			= name.strip()
    size			= g_match.group( 'size' )
    require			= g_match.group( 'require' )
    if not size:
        # eg. default or inverse required/size ratio iff require provided.  Otherwise can't guess.
        if size_default:
            size		= size_default
        elif require:
            require		= int( require )
            size		= int( require / group_parser.REQUIRED_RATIO + 0.5 )
            if size == 1 or require == 1:
                size		= require
        else:
            size		= 1  # No spec, no require; default to group size of 1
    size			= int( size )
    if not require:
        # eg. 2/4, 3/5 for size producing require > 1; else, require = size (avoids 1/N groups)
        require			= int( size * group_parser.REQUIRED_RATIO + 0.5 )
        if size == 1 or require == 1:
            require		= size
    require			= int(require)
    if size < 1 or require > size or ( require == 1 and size > 1 ):
        raise ValueError( f"Impossible group specification from {group_spec!r} w/ default size {size_default!r}: {name,(require,size)!r}" )

    return (name, (require, size))
group_parser.REQUIRED_RATIO	= 1/2  # noqa: E305
group_parser.RE			= re.compile(
    r"""
        ^
        \s*
        (?P<name> [^\d(/]+ )?
        \s*
        [(]?
        \s*
        (?:
            (?P<require> \d* )
            \s*
            [/]
        )?
        \s*
        (?:
            (?P<size> \d* )
            \s*
        )?
        [)]?
        \s*
        $
    """, re.VERBOSE )


def language_parser(language: str) -> Dict[Tuple[str, Tuple[int, int]], Dict[Union[str, int], Tuple[int, int]]]:
    """
    Parse a SLIP-39 language dialect specification.

            optional          sep    default comma-separated mnemonic
         name a secret spec          group thresholds (optional if no /)
        --------------------- --- -------------------------------------- -

       "Name threshold/groups"
        ^^^^^^^^^^^^^^^^^^^^^
        - no separator or commas, must be a secret encoding specification

                                 "group1 thresh1/mnems1, g2(t2/n1) ..."
                                  ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^
        - commas; can't be a secret encoding spec, so must be group specs

        Name threshold/groups [;: group1 thresh1/mnems1, g2(t2/n1) ... ]
        ^^^^^^^^^^^^^^^^^^^^^     ^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^
        - separator; must be both a secret encoding spec, and 0 or more group specs
        - spec(s) may be partial, eg. "3" (size) or "3/" (threshold
          - sensible defaults are deduced for missing specs, if possible

    {
      ("Name",(threshold/groups)): {
        "group1": (thresh1/mnems1),
        "g2":     (t2/n2),
      }
    }

    """
    s_match			= language_parser.RE.match(language)
    if not s_match and language.strip():
        raise ValueError( f"Invalid SLIP-39 specification: {language!r}" )

    groups			= s_match and s_match.group("groups") or ""
    groups_list			= groups.strip().split(",")
    secret			= s_match and s_match.group("secret") or ""
    s_size_default		= len(groups_list) if groups_list else None
    s_name, (s_thresh, s_size)	= group_parser(secret, size_default=s_size_default)
    groups_list		       += [''] * (s_size - len(groups_list))  # default any missing group specs

    g_names, g_sizes		= [], []
    for group in groups_list:
        # Default size inferred from Fibonacci sequence of mnemonics required by default
        size_default		= None if len(g_sizes) < 2 else min(
            MAX_SHARE_COUNT,
            2 * ( g_sizes[-1][0] + g_sizes[-2][0] )
        )
        g_name, g_dims		= group_parser(group, size_default=size_default)
        if not g_name:
            g_name		= len(g_sizes)
        g_names.append(g_name)
        g_sizes.append(g_dims)

    return { (s_name.strip(), (s_thresh, s_size)): dict(zip(g_names, g_sizes)) }
language_parser.REQUIRED_RATIO	= 1/2  # noqa: E305
language_parser.RE		= re.compile(
    r"""
        ^
        \s*
        (?P<secret>		# Any single name and/or spec w/ no separator or comma
            (
                [\w\s]* \d* \s* /? \s* \d*
            )
        )?
        \s* [\[<{;:]? \s*	# An optional separator or bracket may appear before group spec(s)
        (?P<groups>		# The group spec(s), comma separated
            (
                [\w\s]* \d* \s* /? \s* \d*
            )
            (
                \s* ,
                [\w\s]* \d* \s* /? \s* \d*
            )*
        )?
        \s* [\]>}]? \s*		# And optionally a trailing inverse bracket
        $
    """, re.VERBOSE)


def ordinal( num ):
    q, mod			= divmod( num, 10 )
    suffix			= q % 10 != 1 and ordinal.suffixes.get(mod) or "th"
    return f"{num}{suffix}"
ordinal.suffixes		= {1: "st", 2: "nd", 3: "rd"}  # noqa: E305


def tabulate_slip39(
    groups: Dict[Union[str, int], Tuple[int, int]],
    group_mnemonics: Sequence[Collection[str]],
    columns: Optional[Union[bool, int]] = None,  # default: columnize, but no wrapping
) -> str:
    """Return SLIP-39 groups with group names/numbers, a separator, and tabulated mnemonics.

    Mnemonics exceeding 'columns' will be wrapped with no prefix except a continuation character.

    The default behavior (columns is falsey) is to NOT wrap the mnemonics (no columns limit).  If
    columns is True or 1 (truthy, but not a specific sensible column size), we'll use the
    tabulate_slip39.default of 20.  Otherwise, we'll use the specified specific columns.

    """
    if not columns:				# False, None, 0
        limit			= 0
    elif int(columns) > 1:			# 2, ...
        limit			= int(columns)
    else:					# True, 1
        limit			= tabulate_slip39.default

    def prefixed( groups, group_mnemonics ):
        for g, ((name, (threshold, count)), mnemonics) in enumerate( zip( groups.items(), group_mnemonics )):
            assert count == len( mnemonics )
            for o, mnem in enumerate( sorted( map( str.split, mnemonics ))):
                siz		= limit or len( mnem )
                end		= len( mnem )
                rows		= ( end + siz - 1 ) // siz
                for r, col in enumerate( range( 0, end, siz )):
                    con 	= ''
                    if count == 1:			# A 1/1
                        if rows == 1:
                            sep	= '━'			# on 1 row
                        elif r == 0:
                            sep = '┭'			# on multiple rows
                            con = '╎'
                        elif r+1 < rows:
                            sep = '├'
                            con = '╎'
                        else:
                            sep = '└'
                    elif rows == 1:			# An N/M w/ full row mnemonics
                        if o == 0:			# on 1 row, 1st mnemonic
                            sep = '┳'
                            con = '╏'
                        elif o+1 < count:
                            sep = '┣'
                            con = '╏'
                        else:
                            sep = '┗'
                    else:				# An N/M, but multi-row mnemonics
                        if o == 0 and r == 0:		# on 1st row, 1st mnemonic
                            sep = '┳'
                            con = '╎'
                        elif r == 0:			# on 1st row, any mnemonic
                            sep = '┣'
                            con = '╎'
                        elif r+1 < rows:		# on mid row, any mnemonic
                            sep = '├'
                            con = '╎'
                        elif o+1 < count:		# on last row, but not last mneonic
                            sep = '└'
                            con = '╏'
                        else:
                            sep = '└'			# on last row of last mnemonic

                    # Output the prefix and separator + mnemonics
                    yield [
                        f"{name} {threshold}/{count} " if o == 0 and col == 0 else ""
                    ] + [
                        ordinal(o+1) if col == 0 else ""
                    ] + [
                        sep
                    ] + mnem[col:col+siz]

                    # And if not the last group and mnemonic, but a last row; Add a blank or continuation row
                    if r+1 == rows and not (g+1 == len(groups) and o+1 == count):
                        yield ["", "", con] if con else [None]

    return tabulate( prefixed( groups, group_mnemonics ), tablefmt='plain' )

tabulate_slip39.default		= 20  # noqa: E305


class SLIP39Mnemonic(IMnemonic):
    """Implements the SLIP39 standard, allowing the creation of mnemonic phrases for
    recovering deterministic keys.

    Here are available ``SLP39_MNEMONIC_WORDS``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | TWENTY                | 20                   |
    +-----------------------+----------------------+
    | THIRTY_THREE          | 33                   |
    +-----------------------+----------------------+
    | FIFTY_NINE            | 59                   |
    +-----------------------+----------------------+

    Here are available ``SLIP39_MNEMONIC_LANGUAGES``:

    +-----------------------+----------------------+
    | Name                  | Value                |
    +=======================+======================+
    | ENGLISH               | english              |
    +-----------------------+----------------------+


    For SLIP-39, the language word dictionary is always the same (english) so is ignored (simply
    used as a label for the generated SLIP-39), but the rest of the language string specifies
    the "dialect" (threshold of groups required/generated, and the threshold of mnemonics
    required/generated in each group).

    The default is 1/1: 1/1 (a single group of 1 required, with 1/1 mnemonic required) by supplying
    a language without further specific secret recovery or group recovery details:

        ""
        "english"
        "Any Label"

    The default progression of group mnemonics required/provided is fibonacci over required:

      - A threshold is 1/2 the specified number of groups/mnemonics (rounded up), and
      - groups of 1/1, 1/1, 2/4 and 3/6, ... mnemonics

    All of these language specifications produce the same 2/4 group SLIP-39 encoding:

        "Johnson 2/4"
        "2: 1/1, 1/1, 2/4, 3/6"
        "Johnson 2/4: Home 1/1, Office 1/1, Fam 2/4, Frens 3/6"

    """

    word_bit_length: int = 10
    words_list_number: int = 1024
    words_list: List[int] = [
        SLIP39_MNEMONIC_WORDS.TWENTY,
        SLIP39_MNEMONIC_WORDS.THIRTY_THREE,
        SLIP39_MNEMONIC_WORDS.FIFTY_NINE,
    ]
    words_to_entropy_strength: Dict[int, int] = {
        SLIP39_MNEMONIC_WORDS.TWENTY: SLIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT,
        SLIP39_MNEMONIC_WORDS.THIRTY_THREE: SLIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX,
        SLIP39_MNEMONIC_WORDS.FIFTY_NINE: SLIP39_ENTROPY_STRENGTHS.FIVE_HUNDRED_TWELVE,
    }
    languages: List[str] = [
        SLIP39_MNEMONIC_LANGUAGES.ENGLISH
    ]
    wordlist_path: Dict[str, str] = {
        SLIP39_MNEMONIC_LANGUAGES.ENGLISH: "slip39/wordlist/english.txt",
    }

    def __init__(self, mnemonic: Union[str, List[str]], **kwargs) -> None:
        # Record the mnemonics, and the specified language.  First handle any custom keywords
        self._tabulate = kwargs.pop("tabulate", False)

        super().__init__(mnemonic, **kwargs)

        # We know that normalize has already validated _mnemonic's length.  Compute the per-mnemonic
        # words for SLIP-39; exactly one of the available SLIP-39 words_list lengths will divide the
        # mnemonics evenly.
        self._words, = filter(lambda w: len(self._mnemonic) % w == 0, self.words_list)

        # If a SLIP-39 language encoding and/or tabulation is desired, remember them.  The default
        # behavior deduces and stores the Mnemonic language; we want to remember any custom
        # encoding supplied.
        if kwargs.get("language"):
            self._language = kwargs.get("language")

    @classmethod
    def name(cls) -> str:
        """
        Get the name of the mnemonic class.

        :return: The name of the entropy class.
        :rtype: str
        """
        return "SLIP39"

    def mnemonic(self) -> str:
        """Get the mnemonic as a single string.

        SLIP-39 Mnemonics usually have multiple lines.  Iterates the _mnemonic words list by the
        computed self.words(), joining each length of words by spaces to for a line, and then joins
        by newlines.

        If a non-default 'tabulate' (eg. True, None, <int>) was specified, attempt to use it and the
        stored SLIP-39 encoding language to inform the tabulation.

        :return: The mnemonic as a single string joined by spaces and newlines.
        :rtype: str

        """
        if self._tabulate is not False:
            # Output the SLIP-39 mnemonics with their encoding language details and desired
            # tabulation.  We'll need to re-deduce the SLIP-39 secret and group specs from
            # _language.  Only if we successfully compute the same number of expected mnemonics and
            # exactly match the expected prefixes, will we assume that everything is OK (someone
            # hasn't created a SLIP39Mnemonic by hand with a custom _language and _mnemonics), and
            # we'll output the tabulated mnemonics.
            ((s_name, (s_thresh, s_size)), groups), = language_parser(self._language).items()
            mnemonic = iter( self._mnemonic )
            try:
                group_mnemonics: List[List[str]] = [
                    [
                        " ".join( next( mnemonic ) for _ in range( self._words ))
                        for _ in range( g_size )
                    ]
                    for (_g_name, (_g_thresh, g_size)) in groups.items()
                ]
            except StopIteration:
                # Too few mnemonics for SLIP-39 deduced from _language?  Ignore and carry on with
                # simple mnemonics output.
                pass
            else:
                extras = list(mnemonic)
                if not extras:
                    # Exactly consumed all _mnemonics according to SLIP-39 language spec!  Success?
                    # Final check; each of the group_mnemonics lists should have a common prefix.
                    def common( strings: List[str] ) -> str:
                        prefix = None
                        for s in strings:
                            if prefix is None:
                                prefix 	= s
                                continue
                            for i, (cp, cs) in enumerate(zip(prefix, s)):
                                if cp != cs:
                                    prefix = prefix[:i]
                                    break
                            if not prefix:
                                break
                        return prefix

                    if all( map( common, group_mnemonics )):
                        return tabulate_slip39(
                            groups=groups,
                            group_mnemonics=group_mnemonics,
                            columns=self._tabulate
                        )

                # Either no common prefix in some group; Invalid deduction of group specs
                # vs. mnemonics, or left-over/insufficient Mnemonics!  Fall through and render it
                # the old-fashioned way...

        mnemonic_chunks: Iterable[List[str]] = zip(*[iter(self._mnemonic)] * self._words)
        mnemonic: Iterable[str] = map(" ".join, mnemonic_chunks)
        return "\n".join(mnemonic)

    @classmethod
    def from_words(cls, words: int, language: str) -> str:
        """Generates a mnemonic phrase from a specified number of words.

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
            entropy=SLIP39Entropy.generate(cls.words_to_entropy_strength[words]), language=language
        )

    @classmethod
    def from_entropy(cls, entropy: Union[str, bytes, IEntropy], language: str, **kwargs) -> str:
        """
        Generates from entropy data.  Any entropy of the correct size can be encoded as SLIP-39.

        :param entropy: The entropy data used to generate the mnemonic phrase.
        :type entropy: Union[str, bytes, IEntropy]
        :param language: The language for the mnemonic phrase.
        :type language: str

        :return: The generated mnemonic phrase.
        :rtype: str
        """
        if isinstance(entropy, str) or isinstance(entropy, bytes):
            return cls.encode(entropy=entropy, language=language, **kwargs)
        elif isinstance(entropy, IEntropy) and entropy.strength() in SLIP39Entropy.strengths:
            return cls.encode(entropy=entropy.entropy(), language=language, **kwargs)
        raise EntropyError(
            "Invalid entropy instance", expected=[str, bytes,]+list(ENTROPIES.dictionary.values()), got=type(entropy)
        )

    @classmethod
    def is_valid_language(cls, language: str) -> bool:
        try:
            language_parser(language)
            return True
        except Exception:
            return False

    @classmethod
    def encode(
        cls,
        entropy: Union[str, bytes],
        language: str,
        passphrase: str = "",
        extendable: bool = True,
        iteration_exponent: int = 1,
        tabulate: bool = False,  # False disables; any other value causes prefixing/columnization
    ) -> str:
        """Encodes entropy into a SLIP-39 mnemonic phrase according to the specified language.

        The language specifies the SLIP-39 encoding parameters, and not the mnemonic language (which
        is always english).  The SLIP-39 encoding has A Name optionally followed by the number of
        required groups / total groups (will be deduced if missing), followed by 1 or more comma
        separated group names, each optionally with a number of mnemonics required to recover the
        group, and optionally with a / followed by the total number of mnemonics to produce.

            Family Name 3:    Home 1,   Office 1,   Fam 2, Frens 3, Other
            Family Name 3/5 < Home 1/1, Office 1/1, Fam 2, Frens 3, Other >
            Family Name 3/5 < Home 1/1, Office 1/1, Fam 2, Frens 3, Other 5/10>


        SLIP-39 mnemonics include a password.  This is normally empty, and is not well supported
        even on Trezor devices.  It is better to use SLIP-39 to encode a BIP-39 Mnemonic's entropy
        and then (after recovering it from SLIP-39), use a BIP-39 passphrase (which is well
        supported across all devices), or use the "Passphrase Wallet" feature of your hardware
        wallet device.

        When a password is supplied to encode, decode will always recover the original entropy with
        the same password.  The 'extendable' feature (now default) of SLIP-39 provides for
        deterministically recovering a deterministic entropy for each *different* password supplied.
        This supports the use case where the original entropy and password is used (but different
        SLIP-39 encoding parameters are supplied) -- but the same decoded wallet entropies are
        desired for multiple different passwords.

        Note that SLIP-39 includes additional entropy in the encoding process, so the same entropy
        and password will always result in different output SLIP-39 mnemonics.

        :param entropy: The entropy to encode into a mnemonic phrase.
        :type entropy: Union[str, bytes]
        :param language: The language for the mnemonic phrase.
        :type language: str
        :param passphrase: The SLIP-39 passphrase (default: "")
        :type passphrase: str
        :param extendable: Derive deterministic entropy for alternate passwords
        :type extendable: bool

        :return: The encoded mnemonic phrase.
        :rtype: str

        """
        entropy: bytes = get_bytes(entropy, unhexlify=True)
        if not SLIP39Entropy.is_valid_bytes_strength(len(entropy)):
            raise EntropyError(
                "Wrong entropy strength", expected=SLIP39Entropy.strengths, got=(len(entropy) * 8)
            )

        ((s_name, (s_thresh, s_size)), groups), = language_parser(language).items()
        assert s_size == len(groups)
        group_mnemonics: Sequence[Collection[str]] = generate_mnemonics(
            group_threshold=s_thresh,
            groups=groups.values(),
            master_secret=entropy,
            passphrase=passphrase.encode('UTF-8'),
            extendable=extendable,
            iteration_exponent=iteration_exponent,
        )

        if tabulate is not False:  # None/0 imply no column limits
            return tabulate_slip39(groups, group_mnemonics, columns=tabulate)
        return "\n".join(sum(group_mnemonics, []))

    @classmethod
    def decode(
        cls, mnemonic: str, passphrase: str = "", language: Optional[str] = None,
    ) -> str:
        """Decodes SLIP-39 mnemonic phrases into its corresponding entropy.

        This method converts a given mnemonic phrase back into its original entropy value.  It
        verifies several internal hashes to ensure the mnemonic and decoding is valid.

        The passphrase has no verification; all derived entropies are considered equivalently valid
        (you can use several passphrases to recover multiple, distinct sets of entropy.)  So, it is
        solely your responsibility to remember your correct passphrase(s): this is a design feature
        of SLIP-39.

        :param mnemonic: The mnemonic phrase to decode.
        :type mnemonic: str
        :param language: The preferred language of the mnemonic phrase
        :type language: Optional[str]
        :param passphrase: The SLIP-39 passphrase (default: "")
        :type passphrase: str

        :return: The decoded entropy as a string.
        :rtype: str

        """
        mnemonic_list: List[str] = cls.normalize(mnemonic)
        try:
            mnemonic_words, = filter(lambda words: len(mnemonic_list) % words == 0, cls.words_list)
            mnemonic_chunks: Iterable[List[str]] = zip(*[iter(mnemonic_list)] * mnemonic_words)
            mnemonic_lines: Iterable[str] = map(" ".join, mnemonic_chunks)
            recovery = RecoveryState()
            for line in mnemonic_lines:
                recovery.add_share(Share.from_mnemonic(line))
                if recovery.is_complete():
                    break
            else:
                raise ValueError(
                    f"Incomplete: found {recovery.groups_complete()}"
                    + f"/{recovery.parameters.group_threshold} groups and "
                    + ", ".join(
                        "/".join(map(lambda x: str(x) if x >= 0 else "?", recovery.group_status(g)))
                        for g in range(recovery.parameters.group_count)
                    )
                    + " mnemonics required"
                )
            entropy: str = bytes_to_string(recovery.recover(passphrase.encode('UTF-8')))
        except Exception as exc:
            raise MnemonicError("Failed to recover SLIP-39 Mnemonics", detail=exc) from exc
        return entropy

    NORMALIZE			= re.compile(
        r"""
            ^
            \s*
            (
                [ \w\d\s()/]*		# Group(1/1) 1st { <-- a single non-word/space/digit separator allowed
                [^\w\d\s()/]		#  Any symbol not comprising a valid group_parser language symbol
            )?
            \s*
            (
                [\w\s]*\w		# word word ... word <-- must end with non-whitespace (strips whitespace)
            )?
            \s*
            $
        """, re.VERBOSE )

    @classmethod
    def normalize(cls, mnemonic: Union[str, List[str]]) -> List[str]:
        """Filter the supplied lines of mnemonics, rejecting groups of mnemonics not evenly divisible by
        one of the recognized SLIP-39 mnemonic lengths.

        Also accepts a single hex raw entropy value (converting it into a simple single-mnemonic
        (1/1 groups) SLIP-39 encoding).

        Filter out any prefixes consisting of word/space symbols followed by a single non-word/space
        symbol, before any number of Mnemonic word/space symbols:

                    Group  1 { word word ...

                    Group  2 ╭ word word ...
                             ╰ word word ...

                    Group  3 ┌ word word ...
                             ├ word word ...
                             └ word word ...
                    ^^^^^^^^ ^ ^^^^^^^^^^...
                           | | |
           word/digit/space* | word/space*
                             |
                  single non-word/digit/space


        Since multi-row mnemonics are possible, we cannot always confirm that the accumulated
        mnemonic size is valid after every mnemonic row.  We can certainly identify the end of a
        mnemonic by a blank row (it doesn't make sense to allow a single Mnemonic to be split across
        blank rows), or the end of input.

        """
        errors			= []
        if isinstance( mnemonic, str ):
            mnemonic_list: List[str] = []

            for line_no, line in enumerate( mnemonic.split("\n")):
                m = cls.NORMALIZE.match( line )
                if not m:
                    errors.append( f"@L{line_no+1}: unrecognized mnemonic line" )
                    continue

                pref, mnem	= m.groups()
                if mnem:
                    mnemonic_list.extend( super().normalize( mnem ))
                else:
                    # Blank lines or lines without Mnemonic skipped.  But they do indicate the end
                    # of a mnemonic!  At this moment, the total accumulated Mnemonic(s) must be
                    # valid -- or the last one must have been bad.
                    word_lengths = list(filter(lambda w: len(mnemonic_list) % w == 0, cls.words_list))
                    if not word_lengths:
                        errors.append( f"@L{line_no}: odd length mnemonic encountered" )
                        break
        else:
            mnemonic_list: List[str] = mnemonic

        # Regardless of the Mnemonic source; the total number of words must be a valid multiple of
        # the SLIP-39 mnemonic word lengths.  Fortunately, the LCM(20, 33) is 660, and LCM(20, 33
        # and 59) is 38940, so we are unlikely to encounter a sufficient body of mnemonics to ever
        # run into an uncertain SLIP-39 Mnemonic length in words.
        word_lengths = list(filter(lambda w: len(mnemonic_list) % w == 0, cls.words_list))
        if not word_lengths:
            errors.append( "Mnemonics not a multiple of valid length, or a single hex entropy value" )
        if errors:
            raise MnemonicError(
                "Invalid SLIP39 Mnemonics",
                expected=f"multiple of {', '.join(map(str, cls.words_list))}",
                got=f"{len(mnemonic_list)} total words",
                detail="; ".join(errors),
            )

        return mnemonic_list
