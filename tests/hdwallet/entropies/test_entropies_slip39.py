#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.entropies.slip39 import (
    SLIP39Entropy, SLIP39_ENTROPY_STRENGTHS
)
from hdwallet.utils import get_bytes
from hdwallet.exceptions import EntropyError


def test_slip39_entropy(data):

    assert SLIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT == 128
    assert SLIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX == 256
    assert SLIP39_ENTROPY_STRENGTHS.FIVE_HUNDRED_TWELVE == 512

    assert SLIP39Entropy.is_valid_strength(strength=SLIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT)
    assert SLIP39Entropy.is_valid_strength(strength=SLIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX)
    assert SLIP39Entropy.is_valid_strength(strength=SLIP39_ENTROPY_STRENGTHS.FIVE_HUNDRED_TWELVE)

    assert SLIP39Entropy.is_valid_bytes_strength(bytes_strength=len(get_bytes(data["entropies"]["SLIP39"]["128"]["entropy"])))
    assert SLIP39Entropy.is_valid_bytes_strength(bytes_strength=len(get_bytes(data["entropies"]["SLIP39"]["256"]["entropy"])))
    assert SLIP39Entropy.is_valid_bytes_strength(bytes_strength=len(get_bytes(data["entropies"]["SLIP39"]["512"]["entropy"])))

    assert SLIP39Entropy(entropy=SLIP39Entropy.generate(strength=SLIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT)).strength() == 128
    assert SLIP39Entropy(entropy=SLIP39Entropy.generate(strength=SLIP39_ENTROPY_STRENGTHS.TWO_HUNDRED_FIFTY_SIX)).strength() == 256
    assert SLIP39Entropy(entropy=SLIP39Entropy.generate(strength=SLIP39_ENTROPY_STRENGTHS.FIVE_HUNDRED_TWELVE)).strength() == 512

    slip39_128 = SLIP39Entropy(entropy=data["entropies"]["SLIP39"]["128"]["entropy"])
    slip39_256 = SLIP39Entropy(entropy=data["entropies"]["SLIP39"]["256"]["entropy"])
    slip39_512 = SLIP39Entropy(entropy=data["entropies"]["SLIP39"]["512"]["entropy"])

    assert slip39_128.name() == data["entropies"]["SLIP39"]["128"]["name"]
    assert slip39_256.name() == data["entropies"]["SLIP39"]["256"]["name"]
    assert slip39_512.name() == data["entropies"]["SLIP39"]["512"]["name"]

    assert slip39_128.strength() == data["entropies"]["SLIP39"]["128"]["strength"]
    assert slip39_256.strength() == data["entropies"]["SLIP39"]["256"]["strength"]
    assert slip39_512.strength() == data["entropies"]["SLIP39"]["512"]["strength"]

    assert slip39_128.entropy() == data["entropies"]["SLIP39"]["128"]["entropy"]
    assert slip39_256.entropy() == data["entropies"]["SLIP39"]["256"]["entropy"]
    assert slip39_512.entropy() == data["entropies"]["SLIP39"]["512"]["entropy"]

    with pytest.raises(EntropyError, match="Invalid entropy data"):
        SLIP39Entropy(entropy="INVALID_ENTROPY")

    with pytest.raises(EntropyError, match="Invalid entropy data"):
        SLIP39Entropy(entropy="f"*(512//4-1))
    with pytest.raises(EntropyError, match="Unsupported entropy strength"):
        SLIP39Entropy(entropy="f"*(512//4-2))
