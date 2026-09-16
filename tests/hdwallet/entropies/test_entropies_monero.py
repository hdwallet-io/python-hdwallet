#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.entropies.monero import (
    MoneroEntropy, MONERO_ENTROPY_STRENGTHS
)
from hdwallet.utils import get_bytes
from hdwallet.exceptions import EntropyError


def test_monero_entropy(data):

    assert MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT == 128
    assert MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX == 256

    assert MoneroEntropy.is_valid_strength(strength=MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT)
    assert MoneroEntropy.is_valid_strength(strength=MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX)

    assert MoneroEntropy.is_valid_bytes_strength(bytes_strength=len(get_bytes(data["entropies"]["Monero"]["128"]["entropy"])))
    assert MoneroEntropy.is_valid_bytes_strength(bytes_strength=len(get_bytes(data["entropies"]["Monero"]["256"]["entropy"])))

    assert MoneroEntropy(entropy=MoneroEntropy.generate(strength=MONERO_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT)).strength() == 128
    assert MoneroEntropy(entropy=MoneroEntropy.generate(strength=MONERO_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX)).strength() == 256

    monero_128 = MoneroEntropy(entropy=data["entropies"]["Monero"]["128"]["entropy"])
    monero_256 = MoneroEntropy(entropy=data["entropies"]["Monero"]["256"]["entropy"])

    assert monero_128.name() == data["entropies"]["Monero"]["128"]["name"]
    assert monero_256.name() == data["entropies"]["Monero"]["256"]["name"]

    assert monero_128.strength() == data["entropies"]["Monero"]["128"]["strength"]
    assert monero_256.strength() == data["entropies"]["Monero"]["256"]["strength"]

    assert monero_128.entropy() == data["entropies"]["Monero"]["128"]["entropy"]
    assert monero_256.entropy() == data["entropies"]["Monero"]["256"]["entropy"]

    with pytest.raises(EntropyError, match="Invalid entropy data"):
        MoneroEntropy(entropy="INVALID_ENTROPY")

    with pytest.raises(EntropyError, match="Unsupported entropy strength"):
        MoneroEntropy(entropy="cdf694ac868efd01673fc51e897c57a0bd428503080ad4c94c7d6f6d13f095fbc8")
