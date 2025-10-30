#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    Optional, Any
)


class Error(Exception):

    def __init__(
        self,
        message: str,
        detail: Optional[str] = None,
        expected: Any = None,
        got: Any = None
    ):
        self._message, self._detail, self._expected, self._got = (
            message, detail, expected, f"'{got}'"
        )

    def __str__(self):
        if self._expected and self._got and self._detail:
            return f"{self._message}, (expected: {self._expected} | got: {self._got}) {self._detail}"
        elif self._expected and self._got and not self._detail:
            return f"{self._message}, (expected: {self._expected} | got: {self._got})"
        elif self._detail:
            return f"{self._message} {self._detail}"
        else:
            return f"{self._message}"


class EntropyError(Error):
    pass


class ChecksumError(Error):
    pass


class MnemonicError(Error):
    pass


class SeedError(Error):
    pass


class HDError(Error):
    pass


class DerivationError(Error):
    pass


class SemanticError(Error):
    pass


class ECCError(Error):
    pass


class CryptocurrencyError(Error):
    pass


class ExtendedKeyError(Error):
    pass


class AddressError(Error):
    pass


class WIFError(Error):
    pass


class SymbolError(Error):
    pass


class NetworkError(Error):
    pass


class PublicKeyError(Error):
    pass


class PrivateKeyError(Error):
    pass


class XPublicKeyError(Error):
    pass


class XPrivateKeyError(Error):
    pass
