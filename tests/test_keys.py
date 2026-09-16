#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

import pytest
import re

from hdwallet.keys import (
    is_valid_key, is_root_key
)
from hdwallet.exceptions import ExtendedKeyError


def test_keys():

    assert is_valid_key("xprv9s21ZrQH143K3hU8mSCiGTDNX8vESS6bVuXKpMgJK8aLfWTsCgakwRfCts6bXoRG51sHYenkyseTeWB12RfS8KgQF7w8e8ner4U7HDBDuMw")
    assert is_root_key("xprv9s21ZrQH143K3hU8mSCiGTDNX8vESS6bVuXKpMgJK8aLfWTsCgakwRfCts6bXoRG51sHYenkyseTeWB12RfS8KgQF7w8e8ner4U7HDBDuMw")
    assert not is_root_key("xprvA31rahaYRvc6tpxRoBUiymeY5k6c2uCQwWtQxRXsU4cX7FmNyL3fg3T9mXyYc2k7huWwaM3Vi19n6tQ21VgXH65Ws7Snz681y3AmqXrNCL1")
    assert is_valid_key("xpub661MyMwAqRbcGBYbsTjidbA75AkiqtpSs8Svck5usU7KYJo1kDu1VDygk8tWBWC2hvmdFBFEwuz1W2aPHsqKjRcye6MeeyDFkRPNbUq73N9")
    assert is_root_key("xpub661MyMwAqRbcGBYbsTjidbA75AkiqtpSs8Svck5usU7KYJo1kDu1VDygk8tWBWC2hvmdFBFEwuz1W2aPHsqKjRcye6MeeyDFkRPNbUq73N9")
    assert not is_root_key("xpub6GAzPQuoyqr6sT251c2dqZkcYU9FZZpvtiJsnADjBxU6yaF577vE6pC9Lyb3ReSLWZsMQMtcVoPKV1qorppQWbTsxwA7r1AgZ9PbfT1iULz")

    assert is_valid_key("xprv3QESAWYc9vDdZiM9o6Z4Dsny5f4zBVdWgdU2YKw25fGyhT8ZgEkkta4kmkFhn875Mq3xUjRaGyhCnFoK1qb7fDELTyCJMTdiatAHuvG8mjjJgfJesQ9AFBikt59YLVgTEn2HhXKYxjmKSvxHZxdQXzF")
    assert is_root_key("xprv3QESAWYc9vDdZiM9o6Z4Dsny5f4zBVdWgdU2YKw25fGyhT8ZgEkkta4kmkFhn875Mq3xUjRaGyhCnFoK1qb7fDELTyCJMTdiatAHuvG8mjjJgfJesQ9AFBikt59YLVgTEn2HhXKYxjmKSvxHZxdQXzF")
    assert not is_root_key("xprv3TFbDUeC4U4KfWsziG2VfvZ4C2b9foDhQcaFc7vgLCduXkWARCHRqPQZDLYvnrxVaYmXdzPyf7aMuA8BaavsBXaMCCs1c7QhoGe7gGHMMTB7uenMe4YBh5XDWFNwfL6754zdagnqMq4AgysHuV5jnEv")

    assert not is_valid_key("xprv9s21ZrQH143K3hU8mSCiGTDNX8vESS6bVuX.............enkyseTeWB12RfS8KgQF7w8e8ne4U7HDBDuMw")
    with pytest.raises(ExtendedKeyError, match=re.escape("Invalid extended(x) key")):
        is_root_key("xprv9s21ZrQH143K3hU8mSCiGTDNX8vESS6bVuX.............enkyseTeWB12RfS8KgQF7w8e8ne4U7HDBDuMw")
