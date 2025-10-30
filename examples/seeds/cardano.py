#!/usr/bin/env python3

from typing import Type

from hdwallet.cryptocurrencies import Cardano
from hdwallet.seeds import (
  SEEDS, ISeed, CardanoSeed
)

data = {
    "name": "Cardano",
    "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "seeds": [
        {
            "seed": "00000000000000000000000000000000",
            "cardano_type": Cardano.TYPES.BYRON_ICARUS
        },
        {
            "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "cardano_type": Cardano.TYPES.BYRON_LEDGER
        },
        {
            "seed": "bc8279bcc79d3cd026cc662d94e88519a0a5e783cccfdb65b0717bc28164dc360777ef6b5eed44440ee892558f19d1b38f508a9851fac42b02d34e240cc61597",
            "cardano_type": Cardano.TYPES.BYRON_LEDGER,
            "passphrase": "talonlab"
        },
        {
            "seed": "dfee64f10fd452c2882951ef64eeb43880aa4304fd11110a2f1b13913f258a9d",
            "cardano_type": Cardano.TYPES.BYRON_LEGACY
        },
        {
            "seed": "00000000000000000000000000000000",
            "cardano_type": Cardano.TYPES.SHELLEY_ICARUS
        },
        {
            "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            "cardano_type": Cardano.TYPES.SHELLEY_LEDGER
        },
        {
            "seed": "bc8279bcc79d3cd026cc662d94e88519a0a5e783cccfdb65b0717bc28164dc360777ef6b5eed44440ee892558f19d1b38f508a9851fac42b02d34e240cc61597",
            "cardano_type": Cardano.TYPES.SHELLEY_LEDGER,
            "passphrase": "talonlab"
        }
    ]
}

CardanoSeedClass: Type[ISeed] = SEEDS.seed(data["name"])

for seed in data["seeds"]:
    cardano_seed_class = CardanoSeedClass(seed["seed"], cardano_type=seed['cardano_type'])
    cardano_seed = CardanoSeed(seed["seed"], cardano_type=seed['cardano_type'])

    # Always provide passphrase=None if not present, like TS
    passphrase = seed.get("passphrase", None)
    cardano_type = seed["cardano_type"]

    print(
        cardano_seed_class.seed() == cardano_seed.seed() ==
        CardanoSeedClass.from_mnemonic(data["mnemonic"], cardano_type=cardano_type, passphrase=passphrase) ==
        CardanoSeed.from_mnemonic(data["mnemonic"], cardano_type=cardano_type, passphrase=passphrase) ==
        seed["seed"], "\n"
    )

    print("Client:", data["name"])
    print("Mnemonic:", data["mnemonic"])
    print("Seed:", seed["seed"])
    print("Cardano Type:", cardano_type, "\n")
