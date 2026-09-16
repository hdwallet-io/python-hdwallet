#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import json
import os
import pytest

from hdwallet.entropies.electrum.v2 import (
    ElectrumV2Entropy, ELECTRUM_V2_ENTROPY_STRENGTHS
)
from hdwallet.utils import get_bytes
from hdwallet.exceptions import EntropyError


def test_electrum_v2_entropy(data):

    assert ELECTRUM_V2_ENTROPY_STRENGTHS.ONE_HUNDRED_THIRTY_TWO == 132
    assert ELECTRUM_V2_ENTROPY_STRENGTHS.TWO_HUNDRED_SIXTY_FOUR == 264

    assert ElectrumV2Entropy.is_valid_strength(strength=ELECTRUM_V2_ENTROPY_STRENGTHS.ONE_HUNDRED_THIRTY_TWO)
    assert ElectrumV2Entropy.is_valid_strength(strength=ELECTRUM_V2_ENTROPY_STRENGTHS.TWO_HUNDRED_SIXTY_FOUR)

    assert ElectrumV2Entropy.are_entropy_bits_enough(entropy=get_bytes(data["entropies"]["Electrum-V2"]["132"]["entropy-not-suitable"]))
    assert ElectrumV2Entropy.are_entropy_bits_enough(entropy=get_bytes(data["entropies"]["Electrum-V2"]["132"]["entropy-suitable"]))
    assert ElectrumV2Entropy.are_entropy_bits_enough(entropy=get_bytes(data["entropies"]["Electrum-V2"]["264"]["entropy-not-suitable"]))
    assert ElectrumV2Entropy.are_entropy_bits_enough(entropy=get_bytes(data["entropies"]["Electrum-V2"]["264"]["entropy-suitable"]))

    assert ElectrumV2Entropy(entropy=data["entropies"]["Electrum-V2"]["264"]["entropy-not-suitable"]).strength() == 264
    assert ElectrumV2Entropy(entropy=data["entropies"]["Electrum-V2"]["132"]["entropy-not-suitable"]).strength() == 132

    assert ElectrumV2Entropy(entropy=ElectrumV2Entropy.generate(strength=ELECTRUM_V2_ENTROPY_STRENGTHS.ONE_HUNDRED_THIRTY_TWO)).strength() == 132
    assert ElectrumV2Entropy(entropy=ElectrumV2Entropy.generate(strength=ELECTRUM_V2_ENTROPY_STRENGTHS.TWO_HUNDRED_SIXTY_FOUR)).strength() == 264

    ev2_128 = ElectrumV2Entropy(entropy=data["entropies"]["Electrum-V2"]["132"]["entropy-suitable"])
    ev2_160 = ElectrumV2Entropy(entropy=data["entropies"]["Electrum-V2"]["264"]["entropy-suitable"])

    assert ev2_128.name() == data["entropies"]["Electrum-V2"]["132"]["name"]
    assert ev2_160.name() == data["entropies"]["Electrum-V2"]["264"]["name"]

    assert ev2_128.strength() == data["entropies"]["Electrum-V2"]["132"]["strength"]
    assert ev2_160.strength() == data["entropies"]["Electrum-V2"]["264"]["strength"]

    assert ev2_128.entropy() == data["entropies"]["Electrum-V2"]["132"]["entropy-suitable"]
    assert ev2_160.entropy() == data["entropies"]["Electrum-V2"]["264"]["entropy-suitable"]

    with pytest.raises(EntropyError, match="Invalid entropy data"):
        ElectrumV2Entropy(entropy="INVALID_ENTROPY")

    with pytest.raises(EntropyError, match="Entropy bits are not enough"):
        ElectrumV2Entropy(entropy="7c2abbf52d1861b978792df3dc88e7e27dbe36c7a0287893")
