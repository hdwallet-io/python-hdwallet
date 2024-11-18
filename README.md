# Hierarchical Deterministic Wallet

> Note: This hdwallet-slip39 package is a temporary upgrade shim for the great hdwallet package
> https://pypi.org/project/hdwallet/.

> Use it only until the upstream hdwallet package merges support for BSC, Nix, etc in :
> https://github.com/meherett/python-hdwallet/pull/1020

> Until then, substitute "hdwallet-slip39" for "hdwallet" in your "pip install" or requirements.txt
> Both supply the hdwallet package, eg. "import hdwallet".  Specify version >= 2.3 to ensure you are
> using this shim.

[![Build Status](https://app.travis-ci.com/meherett/python-hdwallet.svg?branch=master)](https://app.travis-ci.com/meherett/python-hdwallet)
[![PyPI Version](https://img.shields.io/pypi/v/hdwallet.svg?color=blue)](https://pypi.org/project/hdwallet)
[![Documentation Status](https://readthedocs.org/projects/hdwallet/badge/?version=master)](https://hdwallet.readthedocs.io)
[![PyPI License](https://img.shields.io/pypi/l/hdwallet?color=black)](https://pypi.org/project/hdwallet)
[![PyPI Python Version](https://img.shields.io/pypi/pyversions/hdwallet.svg)](https://pypi.org/project/hdwallet)
[![Coverage Status](https://coveralls.io/repos/github/meherett/python-hdwallet/badge.svg?branch=master)](https://coveralls.io/github/meherett/python-hdwallet)

Python-based library for the implementation of a hierarchical deterministic wallet generator for more than 140+ multiple cryptocurrencies.
It allows the handling of multiple coins, multiple accounts, external and internal chains per account and millions of addresses per chain.

![HDWallet-CLI](https://raw.githubusercontent.com/meherett/python-hdwallet/master/docs/static/svg/hdwallet-cli.svg)

For more info see the BIP specs.

| BIP's                                                                    | Titles                                                     |
| :----------------------------------------------------------------------- | :--------------------------------------------------------- |
| [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)  | Mnemonic code for generating deterministic keys            |
| [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)  | Deterministic Entropy From BIP32 Keychains                 |
| [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)  | Hierarchical Deterministic Wallets                         |
| [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)  | Multi-Account Hierarchy for Deterministic Wallets          |
| [BIP49](https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki)  | Derivation scheme for P2WPKH-nested-in-P2SH based accounts |
| [BIP84](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)  | Derivation scheme for P2WPKH based accounts                |
| [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki) | Segregated Witness (Consensus layer)                       |

## Installation

The easiest way to install `hdwallet` is via pip:

```
pip install hdwallet
```

To install `hdwallet` command line interface globally, for Linux `sudo` may be required:

```
pip install hdwallet[cli]
```

If you want to run the latest version of the code, you can install from the git:

```
pip install git+git://github.com/meherett/python-hdwallet.git
```

For the versions available, see the [tags on this repository](https://github.com/meherett/python-hdwallet/tags).

## Quick Usage

Simple Bitcoin mainnet HDWallet generator:

```python
#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.utils import generate_entropy
from hdwallet.symbols import BTC as SYMBOL
from typing import Optional

import json

# Choose strength 128, 160, 192, 224 or 256
STRENGTH: int = 160  # Default is 128
# Choose language english, french, italian, spanish, chinese_simplified, chinese_traditional, japanese or korean
LANGUAGE: str = "korean"  # Default is english
# Generate new entropy hex string
ENTROPY: str = generate_entropy(strength=STRENGTH)
# Secret passphrase for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"

# Initialize Bitcoin mainnet HDWallet
hdwallet: HDWallet = HDWallet(symbol=SYMBOL, use_default_path=False)
# Get Bitcoin HDWallet from entropy
hdwallet.from_entropy(
    entropy=ENTROPY, language=LANGUAGE, passphrase=PASSPHRASE
)

# Derivation from path
# hdwallet.from_path("m/44'/0'/0'/0/0")
# Or derivation from index
hdwallet.from_index(44, hardened=True)
hdwallet.from_index(0, hardened=True)
hdwallet.from_index(0, hardened=True)
hdwallet.from_index(0)
hdwallet.from_index(0)

# Print all Bitcoin HDWallet information's
print(json.dumps(hdwallet.dumps(), indent=4, ensure_ascii=False))
```

<details open>
  <summary>Output</summary><br/>

```json5
{
    "cryptocurrency": "Bitcoin",
    "symbol": "BTC",
    "network": "mainnet",
    "strength": 160,
    "entropy": "c5b0d0ee698f3f72b6265f1bc591f8f2d7afa6dd",
    "mnemonic": "주일 액수 명단 천둥 해수욕장 전망 추천 직업 그룹 단위 신체 파란색 시청 천천히 스트레스",
    "language": "korean",
    "passphrase": null,
    "seed": "5a9b9667ccd07b3c641b1ba95e9119dd1d5a3034fd46cd2f27fc1f160c7dcd824fc0ab4710a9ae90582dffc3b0803bcbc0a8160feeaab4c70511c5035859decf",
    "root_xprivate_key": "xprv9s21ZrQH143K2qMHU8aghJ4MoQR5g5mowXbeP2vCP937bseZGX929dmJudL7u4xRxtKvh58pxz1PhtCbWW2yUH14jdduKVMV9FkBMpM2Hyw",
    "root_xpublic_key": "xpub661MyMwAqRbcFKRkaA7h4S16MSFa5YVfJkXFBRKowUa6Ufyhp4TGhS5nkvkLXSmdNjoszzDkU26WW2rg1zBsQBt6Pv3T8oLEAExGHD3hcQs",
    "xprivate_key": "xprvA2YyMZWyPK2xo4eZgyypp2CzcHnxNzGbruGg7vmgaAVCtBtrjwzuhXJBNM3FrwBh85ajxHErNR6ByN77WJARpC1HDC7kTwa2yr7Mu9Pz5Qq",
    "xpublic_key": "xpub6FYKm53sDgbG1Yj2o1WqBA9jAKdSnSzTE8CGvKBJ8W2BkzE1HVKAFKcfDcCHKpL5BQRg2HjbNSt55jpFshY7W1KFtp7zjB3DhNAmiFv6kzB",
    "uncompressed": "081016370b45d7e23bd89b07d6886036f5e4df9a129eee3b488c177ba7881856e24d337b280f9d32539a22445e567543b39b708edf5289442f36dcde958a3433",
    "compressed": "03081016370b45d7e23bd89b07d6886036f5e4df9a129eee3b488c177ba7881856",
    "chain_code": "cf9ee427ed8073e009a5743056e8cf19167f67ca5082c2c6635b391e9a4e0b0d",
    "private_key": "f79495fda777197ce73551bcd8e162ceca19167575760d3cc2bced4bf2a213dc",
    "public_key": "03081016370b45d7e23bd89b07d6886036f5e4df9a129eee3b488c177ba7881856",
    "wif": "L5WyVfBu8Sz3iGZtrwJVSP2wDJmu7HThGd1EGekFBnviWgzLXpJd",
    "finger_print": "ac13e305",
    "semantic": "p2pkh",
    "path": "m/44'/0'/0'/0/0",
    "hash": "ac13e305a88bd9968f1c058fcf5d9a6b1b9ef484",
    "addresses": {
        "p2pkh": "1Ggs3kkNrPPWoW17iDFQWgMdw3CD8BzBiv",
        "p2sh": "3GQVUFePz517Hf61Vsa9H2tHj5jw5y6ngV",
        "p2wpkh": "bc1q4sf7xpdg30vedrcuqk8u7hv6dvdeaayy3uw5cj",
        "p2wpkh_in_p2sh": "3JyV5aSgdVYEjQodPWHfvehQ5227EDr3sN",
        "p2wsh": "bc1qnk0s9q4379n6v9vg0lnhdu5qhjyx99u2xm238pmckmjg9v29q54saddzp9",
        "p2wsh_in_p2sh": "3MmsEoP7GLHzuLVgkAtcRtyXLTWh8zNAcd"
    }
}
```
</details>

Ethereum mainnet [Ganache](https://github.com/trufflesuite/ganache) wallet look's like:

```python
#!/usr/bin/env python3

from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.derivations import BIP44Derivation
from hdwallet.utils import generate_mnemonic
from typing import Optional

# Generate english mnemonic words
MNEMONIC: str = generate_mnemonic(language="english", strength=128)
# Secret passphrase/password for mnemonic
PASSPHRASE: Optional[str] = None  # "meherett"

# Initialize Ethereum mainnet BIP44HDWallet
bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
# Get Ethereum BIP44HDWallet from mnemonic
bip44_hdwallet.from_mnemonic(
    mnemonic=MNEMONIC, language="english", passphrase=PASSPHRASE
)
# Clean default BIP44 derivation indexes/paths
bip44_hdwallet.clean_derivation()

print("Mnemonic:", bip44_hdwallet.mnemonic())
print("Base HD Path:  m/44'/60'/0'/0/{address_index}", "\n")

# Get Ethereum BIP44HDWallet information's from address index
for address_index in range(10):
    # Derivation from Ethereum BIP44 derivation path
    bip44_derivation: BIP44Derivation = BIP44Derivation(
        cryptocurrency=EthereumMainnet, account=0, change=False, address=address_index
    )
    # Drive Ethereum BIP44HDWallet
    bip44_hdwallet.from_path(path=bip44_derivation)
    # Print address_index, path, address and private_key
    print(f"({address_index}) {bip44_hdwallet.path()} {bip44_hdwallet.address()} 0x{bip44_hdwallet.private_key()}")
    # Clean derivation indexes/paths
    bip44_hdwallet.clean_derivation()
```

<details open>
  <summary>Output</summary><br/>

```shell script
Mnemonic: bright demand olive glance crater key head glory quantum leisure intact age
Base HD Path:  m/44'/60'/0'/0/{address_index}

(0) m/44'/60'/0'/0/0 0x3a149f0c5dc5c0F1E29e573215C23710dE9c4f87 0xa45f9af43912fdd5e88c492226be082029f257681d4b3e73b68be535d2fb0526
(1) m/44'/60'/0'/0/1 0x9e8A4fD9bA74DbB0c7F465EF56b47489793AA102 0x6e5ab2a3ae20c7b3a1c0645b03689e88e8cdff16f6a39d6a420bfebc20e8a941
(2) m/44'/60'/0'/0/2 0x08Eb0646ddc52E12a03215b94b244B674e9D7a0F 0x938caf07197eda13679bfd88df7e5f6eac3cd9f9248ed445f1a0e084a3e9417c
(3) m/44'/60'/0'/0/3 0x6dB1Ac10bbbE7bdc6bcB246E2Dd36884c346CbE8 0x304e9bebaeef3f4ae7c4d2ef268f40f503d8f47fd2621a575d8f73f49762cbc0
(4) m/44'/60'/0'/0/4 0xd528281f804D950c743Ca48FCcC3D76A3d9AcD5C 0x82a0284b443ec73884806ac9450f09110d8dba024120985431b80a520b3f2911
(5) m/44'/60'/0'/0/5 0xaF24cc02Fd5E0285237677cDDD00ae8E4a9d6E5E 0xb03c61e992f5475222295077a89cf35011984dcdcd1da3666ebffc9ebefe22a9
(6) m/44'/60'/0'/0/6 0x55A972f207DB3498DCBbD97062472A5c10b3266b 0xc003175828a6f768610fb2396b3fcec7fa1957770de2462b9e6d3a0a23346c76
(7) m/44'/60'/0'/0/7 0x7e62C187e597Fc544D5769a38A8e026F5529c81B 0x04bfcff46587fd98e682e3b7acff720051b1b0bee3309fb13703338bbde211cd
(8) m/44'/60'/0'/0/8 0x7aF4A78000032a3FBaF4Ac5a5f64a50FF69f0442 0x1b642b77519cf6e6107827e4773a15975edda6471ff90735e2fc0cf7d8560ac8
(9) m/44'/60'/0'/0/9 0x379a25BB89043f8b875A73eA61aF4F7b70cD73e5 0x4f9fb333faf8ecf8f22d212a0b1c946e4d4c32fa0b7794326038d464b241d771
```
</details>

[Click this to see more examples :)](https://github.com/meherett/python-hdwallet/blob/master/examples)

## Development

To get started, just fork this repo, clone it locally, and run:

```
pip install -e .[cli,tests,docs] -r requirements.txt
```

## Testing

You can run the tests with:

```
pytest
```

Or use `tox` to run the complete suite against the full set of build targets, or pytest to run specific 
tests against a specific version of Python.

## Contributing

Feel free to open an [issue](https://github.com/meherett/hdwallet/issues) if you find a problem,
or a pull request if you've solved an issue. And also any help in testing, development,
documentation and other tasks is highly appreciated and useful to the project.
There are tasks for contributors of all experience levels.

For more information, see the [CONTRIBUTING.md](https://github.com/meherett/hdwallet/blob/master/CONTRIBUTING.md) file.

## Available Cryptocurrencies

This library simplifies the process of creating a new hierarchical deterministic wallets for:

| Cryptocurrencies                                                  |       Symbols        | Mainnet | Testnet | Segwit | Coin Type |     Default Paths     |
|:------------------------------------------------------------------|:--------------------:|:-------:|:-------:|:------:|:---------:|:---------------------:|
| Anon                                                              |        `ANON`        |   Yes   |   No    |   No   |    220    |  `m/44'/220'/0'/0/0`  |
| Argoneum                                                          |        `AGM`         |   Yes   |   No    |   No   |    421    |  `m/44'/421'/0'/0/0`  |
| Artax                                                             |        `XAX`         |   Yes   |   No    |   No   |    219    |  `m/44'/219'/0'/0/0`  |
| Aryacoin                                                          |        `AYA`         |   Yes   |   No    |   No   |    357    |  `m/44'/357'/0'/0/0`  |
| Asiacoin                                                          |         `AC`         |   Yes   |   No    |   No   |    51     |  `m/44'/51'/0'/0/0`   |
| Atom                                                              |        `ATOM`        |   Yes   |   No    |  Yes   |    118    |  `m/44'/118'/0'/0/0`  |
| Auroracoin                                                        |        `AUR`         |   Yes   |   No    |   No   |    85     |  `m/44'/85'/0'/0/0`   |
| Axe                                                               |        `AXE`         |   Yes   |   No    |   No   |   4242    | `m/44'/4242'/0'/0/0`  |
| Bata                                                              |        `BTA`         |   Yes   |   No    |   No   |    89     |  `m/44'/89'/0'/0/0`   |
| Beetle Coin                                                       |        `BEET`        |   Yes   |   No    |   No   |    800    |  `m/44'/800'/0'/0/0`  |
| Bela Coin                                                         |        `BELA`        |   Yes   |   No    |   No   |    73     |  `m/44'/73'/0'/0/0`   |
| Bit Cloud                                                         |        `BTDX`        |   Yes   |   No    |   No   |    218    |  `m/44'/218'/0'/0/0`  |
| Bit Send                                                          |        `BSD`         |   Yes   |   No    |   No   |    91     |  `m/44'/91'/0'/0/0`   |
| [Bitcoin Cash](https://github.com/bitcoincashorg/bitcoincash.org) |        `BCH`         |   Yes   |   No    |  Yes   |    145    |  `m/44'/145'/0'/0/0`  |
| [Bitcoin Gold](https://github.com/BTCGPU/BTCGPU)                  |        `BTG`         |   Yes   |   No    |  Yes   |    156    |  `m/44'/156'/0'/0/0`  |
| [Bitcoin](https://github.com/bitcoin/bitcoin)                     |   `BTC`, `BTCTEST`   |   Yes   |   Yes   |  Yes   |     0     |   `m/44'/0'/0'/0/0`   |
| Bitcoin Plus                                                      |        `XBC`         |   Yes   |   No    |   No   |    65     |  `m/44'/65'/0'/0/0`   |
| Bitcoin SV                                                        |        `BSV`         |   Yes   |   No    |   No   |    236    |  `m/44'/236'/0'/0/0`  |
| BitcoinZ                                                          |        `BTCZ`        |   Yes   |   No    |   No   |    177    |  `m/44'/177'/0'/0/0`  |
| Bitcore                                                           |        `BTX`         |   Yes   |   No    |  Yes   |    160    |  `m/44'/160'/0'/0/0`  |
| Blackcoin                                                         |        `BLK`         |   Yes   |   No    |   No   |    10     |  `m/44'/10'/0'/0/0`   |
| Block Stamp                                                       |        `BST`         |   Yes   |   No    |  Yes   |    254    |  `m/44'/254'/0'/0/0`  |
| Blocknode                                                         |   `BND`, `BNDTEST`   |   Yes   |   Yes   |   No   |   2941    | `m/44'/2941'/0'/0/0`  |
| Bolivarcoin                                                       |        `BOLI`        |   Yes   |   No    |   No   |    278    |  `m/44'/278'/0'/0/0`  |
| Brit Coin                                                         |        `BRIT`        |   Yes   |   No    |   No   |    70     |  `m/44'/70'/0'/0/0`   |
| CPU Chain                                                         |        `CPU`         |   Yes   |   No    |  Yes   |    363    |  `m/44'/363'/0'/0/0`  |
| Canada eCoin                                                      |        `CDN`         |   Yes   |   No    |   No   |    34     |  `m/44'/34'/0'/0/0`   |
| Cannacoin                                                         |        `CCN`         |   Yes   |   No    |   No   |    19     |  `m/44'/19'/0'/0/0`   |
| Clams                                                             |        `CLAM`        |   Yes   |   No    |   No   |    23     |  `m/44'/23'/0'/0/0`   |
| Club Coin                                                         |        `CLUB`        |   Yes   |   No    |   No   |    79     |  `m/44'/79'/0'/0/0`   |
| Compcoin                                                          |        `CMP`         |   Yes   |   No    |   No   |    71     |  `m/44'/71'/0'/0/0`   |
| Crane Pay                                                         |        `CRP`         |   Yes   |   No    |  Yes   |   2304    | `m/44'/2304'/0'/0/0`  |
| Crave                                                             |       `CRAVE`        |   Yes   |   No    |   No   |    186    |  `m/44'/186'/0'/0/0`  |
| [Dash](https://github.com/dashpay/dash)                           |  `DASH`, `DASHTEST`  |   Yes   |   Yes   |   No   |     5     |   `m/44'/5'/0'/0/0`   |
| Deep Onion                                                        |       `ONION`        |   Yes   |   No    |  Yes   |    305    |  `m/44'/305'/0'/0/0`  |
| Defcoin                                                           |        `DFC`         |   Yes   |   No    |   No   |   1337    | `m/44'/1337'/0'/0/0`  |
| Denarius                                                          |        `DNR`         |   Yes   |   No    |   No   |    116    |  `m/44'/116'/0'/0/0`  |
| Diamond                                                           |        `DMD`         |   Yes   |   No    |   No   |    152    |  `m/44'/152'/0'/0/0`  |
| Digi Byte                                                         |        `DGB`         |   Yes   |   No    |  Yes   |    20     |  `m/44'/20'/0'/0/0`   |
| Digitalcoin                                                       |        `DGC`         |   Yes   |   No    |   No   |    18     |  `m/44'/18'/0'/0/0`   |
| [Dogecoin](https://github.com/dogecoin/dogecoin)                  |  `DOGE`, `DOGETEST`  |   Yes   |   Yes   |   No   |     3     |   `m/44'/3'/0'/0/0`   |
| EDR Coin                                                          |        `EDRC`        |   Yes   |   No    |   No   |    56     |  `m/44'/56'/0'/0/0`   |
| Ecoin                                                             |        `ECN`         |   Yes   |   No    |   No   |    115    |  `m/44'/115'/0'/0/0`  |
| Einsteinium                                                       |        `EMC2`        |   Yes   |   No    |   No   |    41     |  `m/44'/41'/0'/0/0`   |
| Elastos                                                           |        `ELA`         |   Yes   |   No    |   No   |   2305    | `m/44'/2305'/0'/0/0`  |
| Energi                                                            |        `NRG`         |   Yes   |   No    |   No   |   9797    | `m/44'/9797'/0'/0/0`  |
| [Ethereum](https://github.com/ethereum/go-ethereum)               |        `ETH`         |   Yes   |   No    |  Yes   |    60     |  `m/44'/60'/0'/0/0`   |
| Europe Coin                                                       |        `ERC`         |   Yes   |   No    |   No   |    151    |  `m/44'/151'/0'/0/0`  |
| Exclusive Coin                                                    |        `EXCL`        |   Yes   |   No    |   No   |    190    |  `m/44'/190'/0'/0/0`  |
| FIX                                                               |   `FIX`, `FIXTEST`   |   Yes   |   Yes   |   No   |    336    |  `m/44'/336'/0'/0/0`  |
| Feathercoin                                                       |        `FTC`         |   Yes   |   No    |   No   |     8     |   `m/44'/8'/0'/0/0`   |
| Firstcoin                                                         |        `FRST`        |   Yes   |   No    |   No   |    167    |  `m/44'/167'/0'/0/0`  |
| Flashcoin                                                         |       `FLASH`        |   Yes   |   No    |   No   |    120    |  `m/44'/120'/0'/0/0`  |
| [Flux](https://github.com/RunOnFlux/fluxd)                        |        `FLUX`        |   Yes   |   No    |   No   |   19167   | `m/44'/19167'/0'/0/0` |
| Fuji Coin                                                         |        `FJC`         |   Yes   |   No    |  Yes   |    75     |  `m/44'/75'/0'/0/0`   |
| GCR Coin                                                          |        `GCR`         |   Yes   |   No    |   No   |    49     |  `m/44'/49'/0'/0/0`   |
| Game Credits                                                      |        `GAME`        |   Yes   |   No    |   No   |    101    |  `m/44'/101'/0'/0/0`  |
| Go Byte                                                           |        `GBX`         |   Yes   |   No    |   No   |    176    |  `m/44'/176'/0'/0/0`  |
| Gridcoin                                                          |        `GRC`         |   Yes   |   No    |   No   |    84     |  `m/44'/84'/0'/0/0`   |
| Groestl Coin                                                      |   `GRS`, `GRSTEST`   |   Yes   |   Yes   |  Yes   |    17     |  `m/44'/17'/0'/0/0`   |
| Gulden                                                            |        `NLG`         |   Yes   |   No    |   No   |    87     |  `m/44'/87'/0'/0/0`   |
| Helleniccoin                                                      |        `HNC`         |   Yes   |   No    |   No   |    168    |  `m/44'/168'/0'/0/0`  |
| Hempcoin                                                          |        `THC`         |   Yes   |   No    |   No   |    113    |  `m/44'/113'/0'/0/0`  |
| Hush                                                              |        `HUSH`        |   Yes   |   No    |   No   |    197    |  `m/44'/197'/0'/0/0`  |
| IX Coin                                                           |        `IXC`         |   Yes   |   No    |   No   |    86     |  `m/44'/86'/0'/0/0`   |
| Insane Coin                                                       |        `INSN`        |   Yes   |   No    |   No   |    68     |  `m/44'/68'/0'/0/0`   |
| Internet Of People                                                |        `IOP`         |   Yes   |   No    |   No   |    66     |  `m/44'/66'/0'/0/0`   |
| Jumbucks                                                          |        `JBS`         |   Yes   |   No    |   No   |    26     |  `m/44'/26'/0'/0/0`   |
| Kobocoin                                                          |        `KOBO`        |   Yes   |   No    |   No   |    196    |  `m/44'/196'/0'/0/0`  |
| Komodo                                                            |        `KMD`         |   Yes   |   No    |   No   |    141    |  `m/44'/141'/0'/0/0`  |
| LBRY Credits                                                      |        `LBC`         |   Yes   |   No    |   No   |    140    |  `m/44'/140'/0'/0/0`  |
| Linx                                                              |        `LINX`        |   Yes   |   No    |   No   |    114    |  `m/44'/114'/0'/0/0`  |
| Litecoin Cash                                                     |        `LCC`         |   Yes   |   No    |   No   |    192    |  `m/44'/192'/0'/0/0`  |
| [Litecoin](https://github.com/litecoin-project/litecoin)          |   `LTC`, `LTCTEST`   |   Yes   |   Yes   |  Yes   |     2     |   `m/44'/2'/0'/0/0`   |
| LitecoinZ                                                         |        `LTZ`         |   Yes   |   No    |   No   |    221    |  `m/44'/221'/0'/0/0`  |
| Lkrcoin                                                           |        `LKR`         |   Yes   |   No    |   No   |    557    |  `m/44'/557'/0'/0/0`  |
| Lynx                                                              |        `LYNX`        |   Yes   |   No    |   No   |    191    |  `m/44'/191'/0'/0/0`  |
| Mazacoin                                                          |        `MZC`         |   Yes   |   No    |   No   |    13     |  `m/44'/13'/0'/0/0`   |
| Megacoin                                                          |        `MEC`         |   Yes   |   No    |   No   |    217    |  `m/44'/217'/0'/0/0`  |
| Minexcoin                                                         |        `MNX`         |   Yes   |   No    |   No   |    182    |  `m/44'/182'/0'/0/0`  |
| Monacoin                                                          |        `MONA`        |   Yes   |   No    |  Yes   |    22     |  `m/44'/22'/0'/0/0`   |
| Monkey Project                                                    |        `MONK`        |   Yes   |   No    |  Yes   |    214    |  `m/44'/214'/0'/0/0`  |
| Myriadcoin                                                        |        `XMY`         |   Yes   |   No    |   No   |    90     |  `m/44'/90'/0'/0/0`   |
| NIX                                                               |        `NIX`         |   Yes   |   No    |  Yes   |    400    |  `m/44'/400'/0'/0/0`  |
| Namecoin                                                          |        `NMC`         |   Yes   |   No    |   No   |     7     |   `m/44'/7'/0'/0/0`   |
| [Navcoin](https://github.com/navcoin/navcoin-core)                |        `NAV`         |   Yes   |   No    |   No   |    130    |  `m/44'/130'/0'/0/0`  |
| Neblio                                                            |        `NEBL`        |   Yes   |   No    |   No   |    146    |  `m/44'/146'/0'/0/0`  |
| Neoscoin                                                          |        `NEOS`        |   Yes   |   No    |   No   |    25     |  `m/44'/25'/0'/0/0`   |
| Neurocoin                                                         |        `NRO`         |   Yes   |   No    |   No   |    110    |  `m/44'/110'/0'/0/0`  |
| New York Coin                                                     |        `NYC`         |   Yes   |   No    |   No   |    179    |  `m/44'/179'/0'/0/0`  |
| Novacoin                                                          |        `NVC`         |   Yes   |   No    |   No   |    50     |  `m/44'/50'/0'/0/0`   |
| NuBits                                                            |        `NBT`         |   Yes   |   No    |   No   |    12     |  `m/44'/12'/0'/0/0`   |
| NuShares                                                          |        `NSR`         |   Yes   |   No    |   No   |    11     |  `m/44'/11'/0'/0/0`   |
| OK Cash                                                           |         `OK`         |   Yes   |   No    |   No   |    69     |  `m/44'/69'/0'/0/0`   |
| [Omni](https://github.com/omnilayer/omnicore)                     |  `OMNI`, `OMNITEST`  |   Yes   |   Yes   |   No   |    200    |  `m/44'/200'/0'/0/0`  |
| Onix Coin                                                         |        `ONX`         |   Yes   |   No    |   No   |    174    |  `m/44'/174'/0'/0/0`  |
| Peercoin                                                          |        `PPC`         |   Yes   |   No    |   No   |     6     |   `m/44'/6'/0'/0/0`   |
| Pesobit                                                           |        `PSB`         |   Yes   |   No    |   No   |    62     |  `m/44'/62'/0'/0/0`   |
| Phore                                                             |        `PHR`         |   Yes   |   No    |   No   |    444    |  `m/44'/444'/0'/0/0`  |
| Pinkcoin                                                          |        `PINK`        |   Yes   |   No    |   No   |    117    |  `m/44'/117'/0'/0/0`  |
| Pivx                                                              |  `PIVX`, `PIVXTEST`  |   Yes   |   Yes   |   No   |    119    |  `m/44'/119'/0'/0/0`  |
| Posw Coin                                                         |        `POSW`        |   Yes   |   No    |   No   |    47     |  `m/44'/47'/0'/0/0`   |
| Potcoin                                                           |        `POT`         |   Yes   |   No    |   No   |    81     |  `m/44'/81'/0'/0/0`   |
| Project Coin                                                      |        `PRJ`         |   Yes   |   No    |   No   |    533    |  `m/44'/533'/0'/0/0`  |
| Putincoin                                                         |        `PUT`         |   Yes   |   No    |   No   |    122    |  `m/44'/122'/0'/0/0`  |
| [Qtum](https://github.com/qtumproject/qtum)                       |  `QTUM`, `QTUMTEST`  |   Yes   |   Yes   |  Yes   |   2301    | `m/44'/2301'/0'/0/0`  |
| RSK                                                               |  `RBTC`, `RBTCTEST`  |   Yes   |   Yes   |   No   |    137    |  `m/44'/137'/0'/0/0`  |
| Rapids                                                            |        `RPD`         |   Yes   |   No    |   No   |    320    |  `m/44'/320'/0'/0/0`  |
| Ravencoin                                                         |        `RVN`         |   Yes   |   No    |   No   |    175    |  `m/44'/175'/0'/0/0`  |
| Reddcoin                                                          |        `RDD`         |   Yes   |   No    |   No   |     4     |   `m/44'/4'/0'/0/0`   |
| Ripple                                                            |        `XRP`         |   Yes   |   No    |   No   |     144   |   `m/44'/144'/0'/0/0` |
| Rubycoin                                                          |        `RBY`         |   Yes   |   No    |   No   |    16     |  `m/44'/16'/0'/0/0`   |
| Safecoin                                                          |        `SAFE`        |   Yes   |   No    |   No   |   19165   | `m/44'/19165'/0'/0/0` |
| Saluscoin                                                         |        `SLS`         |   Yes   |   No    |   No   |    572    |  `m/44'/572'/0'/0/0`  |
| Scribe                                                            |       `SCRIBE`       |   Yes   |   No    |   No   |    545    |  `m/44'/545'/0'/0/0`  |
| [Shadow Cash](https://github.com/shadowproject/shadow)            |   `SDC`, `SDCTEST`   |   Yes   |   Yes   |   No   |    35     |  `m/44'/35'/0'/0/0`   |
| Slimcoin                                                          |   `SLM`, `SLMTEST`   |   Yes   |   Yes   |   No   |    63     |  `m/44'/63'/0'/0/0`   |
| Smileycoin                                                        |        `SMLY`        |   Yes   |   No    |   No   |    59     |  `m/44'/59'/0'/0/0`   |
| Solarcoin                                                         |        `SLR`         |   Yes   |   No    |   No   |    58     |  `m/44'/58'/0'/0/0`   |
| Stash                                                             |       `STASH`        |   Yes   |   No    |   No   |   49344   | `m/44'/49344'/0'/0/0` |
| Stratis                                                           | `STRAT`, `STRATTEST` |   Yes   |   Yes   |   No   |    105    |  `m/44'/105'/0'/0/0`  |
| Sugarchain                                                        | `SUGAR`, `SUGARTEST` |   Yes   |   Yes   |  Yes   |    408    |  `m/44'/408'/0'/0/0`  |
| Syscoin                                                           |        `SYS`         |   Yes   |   No    |  Yes   |    57     |  `m/44'/57'/0'/0/0`   |
| TOA Coin                                                          |        `TOA`         |   Yes   |   No    |   No   |    159    |  `m/44'/159'/0'/0/0`  |
| Thought AI                                                        |        `THT`         |   Yes   |   No    |   No   |    502    |  `m/44'/502'/0'/0/0`  |
| [Tron](https://github.com/tronprotocol/java-tron)                 |        `TRX`         |   Yes   |   No    |   No   |    195    |  `m/44'/195'/0'/0/0`  |
| Twins                                                             | `TWINS`, `TWINSTEST` |   Yes   |   Yes   |   No   |    970    |  `m/44'/970'/0'/0/0`  |
| Ultimate Secure Cash                                              |        `USC`         |   Yes   |   No    |   No   |    112    |  `m/44'/112'/0'/0/0`  |
| Unobtanium                                                        |        `UNO`         |   Yes   |   No    |   No   |    92     |  `m/44'/92'/0'/0/0`   |
| Virtual Cash                                                      |        `VASH`        |   Yes   |   No    |   No   |    33     |  `m/44'/33'/0'/0/0`   |
| Vcash                                                             |         `VC`         |   Yes   |   No    |   No   |    127    |  `m/44'/127'/0'/0/0`  |
| Verge Currency                                                    |        `XVG`         |   Yes   |   No    |   No   |    77     |  `m/44'/77'/0'/0/0`   |
| Vertcoin                                                          |        `VTC`         |   Yes   |   No    |  Yes   |    28     |  `m/44'/28'/0'/0/0`   |
| [Viacoin](https://github.com/viacoin/viacore-viacoin)             |   `VIA`, `VIATEST`   |   Yes   |   Yes   |  Yes   |    14     |  `m/44'/14'/0'/0/0`   |
| Vivo                                                              |        `VIVO`        |   Yes   |   No    |   No   |    166    |  `m/44'/166'/0'/0/0`  |
| Whitecoin                                                         |        `XWC`         |   Yes   |   No    |   No   |    559    |  `m/44'/559'/0'/0/0`  |
| Wincoin                                                           |         `WC`         |   Yes   |   No    |   No   |    181    |  `m/44'/181'/0'/0/0`  |
| XUEZ                                                              |        `XUEZ`        |   Yes   |   No    |   No   |    225    |  `m/44'/225'/0'/0/0`  |
| [XinFin](https://github.com/XinFinOrg/XDPoSChain)                 |        `XDC`         |   Yes   |   No    |  Yes   |    550    |  `m/44'/550'/0'/0/0`  |
| [Ycash](https://github.com/ycashfoundation/ycash)                 |        `YEC`         |   Yes   |   No    |   No   |    347    |  `m/44'/347'/0'/0/0`  |
| ZClassic                                                          |        `ZCL`         |   Yes   |   No    |   No   |    147    |  `m/44'/147'/0'/0/0`  |
| [Zcash](https://github.com/zcash/zcash)                           |   `ZEC`, `ZECTEST`   |   Yes   |   Yes   |   No   |    133    |  `m/44'/133'/0'/0/0`  |
| Zencash                                                           |        `ZEN`         |   Yes   |   No    |   No   |    121    |  `m/44'/121'/0'/0/0`  |

## Donations

If You found this tool helpful consider making a donation:

| Coins                         | Addresses                                  |
| ----------------------------- | :----------------------------------------: |
| Bitcoin `BTC`                 | 3GGNPvgbSpMHShcaZJGDXQn5wUJyTz7uoC         |
| Ethereum `ETH`, Tether `USDT` | 0x342798bbe9731a91e0557fa8ab0bce1eae6d6ae3 |

## License

Distributed under the [MIT](https://github.com/meherett/python-hdwallet/blob/master/LICENSE) license. See ``LICENSE`` for more information.
