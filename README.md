# Hierarchical Deterministic (HD) Wallet

[![Build Status](https://img.shields.io/github/actions/workflow/status/hdwallet-io/python-hdwallet/build.yml)](https://github.com/hdwallet-io/python-hdwallet/actions/workflows/build.yml)
[![PyPI Version](https://img.shields.io/pypi/v/hdwallet.svg?color=blue)](https://pypi.org/project/hdwallet)
[![Documentation Status](https://readthedocs.org/projects/hdwallet/badge/?version=master)](https://hdwallet.readthedocs.io)
[![PyPI License](https://img.shields.io/pypi/l/hdwallet?color=black)](https://pypi.org/project/hdwallet)
[![PyPI Python Version](https://img.shields.io/pypi/pyversions/hdwallet.svg)](https://pypi.org/project/hdwallet)
[![Coverage Status](https://coveralls.io/repos/github/hdwallet-io/python-hdwallet/badge.svg?branch=master)](https://coveralls.io/github/hdwallet-io/python-hdwallet)

Python-based library for the implementation of a Hierarchical Deterministic (HD) Wallet generator supporting more than 200 cryptocurrencies.
It allows the handling of multiple coins, multiple accounts, external and internal chains per account, and millions of addresses per chain.

> The library is designed to be flexible and scalable, making it ideal for developers who need to integrate multi-currency wallet functionalities into their applications. 
> It supports standard protocols for compatibility with other wallets and services, offering features like secure seed creation, efficient key management, and easy account handling.
>
> This library simplifies the complexity of blockchain interactions and enhances security for end-users. 

| Components                    | Protocols                                                                                                                                                                                                                                                                                                                                                                                                             |
|:------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cryptocurrencies              | <a href="#supported-cryptocurrencies">#supported-cryptocurrencies</a>                                                                                                                                                                                                                                                                                                                                                 |
| Entropies                     | ``Algorand``, ``BIP39``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``                                                                                                                                                                                                                                                                                                                                                 |
| Mnemonics                     | ``Algorand``, ``BIP39``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``                                                                                                                                                                                                                                                                                                                                                 |
| Seeds                         | ``Algorand``, ``BIP39``, ``Cardano``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``                                                                                                                                                                                                                                                                                                                                    |
| Elliptic Curve Cryptography's | ``Kholaw-Ed25519``, ``SLIP10-Ed25519``, ``SLIP10-Ed25519-Blake2b``, ``SLIP10-Ed25519-Monero``, ``SLIP10-Nist256p1``, ``SLIP10-Secp256k1``                                                                                                                                                                                                                                                                             |
| Hierarchical Deterministic's  | ``BIP32``, ``BIP44``, ``BIP49``, ``BIP84``, ``BIP86``, ``BIP141``, ``Cardano``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``                                                                                                                                                                                                                                                                                          |
| Derivations                   | ``BIP44``, ``BIP49``, ``BIP84``, ``BIP86``, ``CIP1852``, ``Custom``, ``Electrum``, ``Monero``, ``HDW (Our own custom derivation)``                                                                                                                                                                                                                                                                                    |
| Addresses                     | ``Algorand``, ``Aptos``, ``Avalanche``, ``Cardano``, ``Cosmos``, ``EOS``, ``Ergo``, ``Ethereum``, ``Filecoin``, ``Harmony``, ``Icon``, ``Injective``, ``Monero``, ``MultiversX``, ``Nano``, ``Near``, ``Neo``, ``OKT-Chain``, ``P2PKH``, ``P2SH``, ``P2TR``, ``P2WPKH``, ``P2WPKH-In-P2SH``, ``P2WSH``, ``P2WSH-In-P2SH``, ``Ripple``, ``Solana``, ``Stellar``, ``Sui``, ``Tezos``, ``Tron``, ``XinFin``, ``Zilliqa`` |
| Others                        | ``BIP38``, ``Wallet Import Format``, ``Serialization``                                                                                                                                                                                                                                                                                                                                                                |

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
pip install git+ssh://github.com/hdwallet-io/python-hdwallet.git
```

For the versions available, see the [tags on this repository](https://github.com/hdwallet-io/python-hdwallet/tags).

## Quick Usage

### Example

A simple Bitcoin HDWallet generator:

```python
#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.entropies import (
    BIP39Entropy, BIP39_ENTROPY_STRENGTHS
)
from hdwallet.mnemonics import BIP39_MNEMONIC_LANGUAGES
from hdwallet.cryptocurrencies import Bitcoin as Cryptocurrency
from hdwallet.hds import BIP32HD
from hdwallet.derivations import CustomDerivation
from hdwallet.const import PUBLIC_KEY_TYPES

import json

# Initialize Bitcoin HDWallet
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP32HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.KOREAN,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase="hdwallet-io"
).from_entropy(  # Get Bitcoin HDWallet from entropy
    entropy=BIP39Entropy(
        entropy=BIP39Entropy.generate(
            strength=BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_SIXTY
        )
    )
).from_derivation(  # Drive from Custom derivation
    derivation=CustomDerivation(
        path="m/0'/0/0"
    )
)

# Print all Bitcoin HDWallet information's
print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))  # dump
# print(json.dumps(hdwallet.dumps(exclude={"indexes"}), indent=4, ensure_ascii=False))  # dumps
```

<details open>
  <summary>Output</summary><br/>

```json
{
    "cryptocurrency": "Bitcoin",
    "symbol": "BTC",
    "network": "mainnet",
    "coin_type": 0,
    "entropy": "00000000000000000000000000000000",
    "strength": 128,
    "mnemonic": "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능",
    "passphrase": "hdwallet-io",
    "language": "Korean",
    "seed": "4e415367c4a4d57ed9737ca50d2f8bf38a274d1d7fb3dd6598c759101c595cdf54045dbaeb216cf3751ce47862c41ff79caf961ca6c2aed11854afeb5efc1ab7",
    "ecc": "SLIP10-Secp256k1",
    "hd": "BIP32",
    "semantic": "p2pkh",
    "root_xprivate_key": "xprv9s21ZrQH143K4L18AD5Ko2ELW8bqaGLW4vfASZzo9yEN8fkZPZLdECXWXAMovtonu7DdEFwJuYH31QT96FWJUfkiLUVT8t8e3WNDiwZkuLJ",
    "root_xpublic_key": "xpub661MyMwAqRbcGp5bGEcLAAB54ASKyj4MS9amExQQiJmM1U5hw6esmzqzNQtquzBRNvLWtPC2kRu2kZR888FSAiZRpvKdjgbmoKRCgGM1YEy",
    "root_private_key": "7f60ec0fa89064a37e208ade560c098586dd887e2133bee4564af1de52bc7f5c",
    "root_wif": "L1VKQooPmgVLD35vHMeprus1zFYx58bHGMfTz8QYTEnRCzbjwMoo",
    "root_chain_code": "e3fa538b530821c258bc7a7915945b7a7184632c1c36a6f165f52690984633b0",
    "root_public_key": "023e23967b818fb3959f2056b6e6449a65c4982c1267398d8897b921ab53b0be4b",
    "strict": true,
    "public_key_type": "compressed",
    "wif_type": "wif-compressed",
    "derivation": {
        "at": {
            "path": "m/0'/0/0",
            "depth": 3,
            "index": 0
        },
        "xprivate_key": "xprv9ygweU6CCkHDimDhPBgbfpi5cLBJpQQhKKRTmn4FdV8QFJ6d2ykk4rwbjftRqZi4qf4NH5ASXnQFYy5misVR3bbLu5pFtNUh83zorMeedVk",
        "xpublic_key": "xpub6CgJ3yd637qWwFJAVDDc2xepAN1oDs8YgYM4aATsBpfP86RmaX4zcfG5avjbFfogEdYRfh7tGjH8sNWpxxsic1aZfaaPVEtZDeCy6rYPL9r",
        "private_key": "be3851aa7822b92deb2f34655e41a40fd510f6cf9aa2a4f0c4d7a4bc81f0ad74",
        "wif": "L3bURmbosdpWYiyn8RvSmg1kkPfw9aqKUhGaPamCsV6p4uwidip9",
        "chain_code": "4d3d731202c9b647b54a3f73de0868f02ac11ba4f9def204ec1b5831334088a9",
        "public_key": "02a6247d244d3bf7b8078940986226756a9eb3aaee97267dabef906c7357f1866b",
        "uncompressed": "04a6247d244d3bf7b8078940986226756a9eb3aaee97267dabef906c7357f1866b2cad34bdb883f6f0230ee513b756815fd8742da754af2d1c40cde277e3302da4",
        "compressed": "02a6247d244d3bf7b8078940986226756a9eb3aaee97267dabef906c7357f1866b",
        "hash": "8af4ba43dcba0b2eac50e5acb44469e6436c0ac6",
        "fingerprint": "8af4ba43",
        "parent_fingerprint": "8ba1670b",
        "addresses": {
            "p2pkh": "1DfjRSmJyQP79AL3Ww7wkSPPH65LCamWv4",
            "p2sh": "35dRc3fmPBMuhfgyKHPUG7sgeyJEw4yEoJ",
            "p2tr": "bc1pp47dx9trjs9307vfnvqtmtjlh7cd9hk45tw6d3t5ezj4u3n5aw5qvrpmum",
            "p2wpkh": "bc1q3t6t5s7uhg9jatzsukktg3rfuepkczkxy8qet0",
            "p2wpkh_in_p2sh": "3CBWzWcMVCSPbUaTMXTHXyWgXLr4JHEYeh",
            "p2wsh": "bc1qnxyylsl2flhdt5nudxpe87s7wssvwc666s064h8xlf2gmr670thsz3y88x",
            "p2wsh_in_p2sh": "3FLAK2eBsFb6rYU8dEHRVrAH18CmgBYWRy"
        }
    }
}
```
</details>

Explore more [Examples](https://github.com/hdwallet-io/python-hdwallet/blob/master/examples)

### Command Line Interface (CLI)

The ``hdwallet`` CLI provides a simple way to generate wallets, derive addresses, and manage keys directly from your terminal, with options for exporting data in JSON and CSV formats. 

![HDWallet-CLI](https://raw.githubusercontent.com/hdwallet-io/python-hdwallet/refs/heads/master/docs/static/svg/hdwallet-cli.svg)

Explore more [Commands](https://github.com/hdwallet-io/python-hdwallet/blob/master/examples#readme)

### Clients

[MetaMask](https://github.com/MetaMask/metamask-extension), [Ganache-CLI](https://github.com/trufflesuite/ganache) or [Hardhat](https://github.com/nomicfoundation/hardhat) wallet look's like:

```python
#!/usr/bin/env python3

from hdwallet import HDWallet
from hdwallet.mnemonics import (
    BIP39Mnemonic, BIP39_MNEMONIC_LANGUAGES, BIP39_MNEMONIC_WORDS
)
from hdwallet.cryptocurrencies import Ethereum as Cryptocurrency
from hdwallet.hds import BIP44HD
from hdwallet.derivations import (
    BIP44Derivation, CHANGES
)

# Initialize Ethereum HDWallet
hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP44HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    passphrase=None  # "hdwallet-io"
).from_mnemonic(   # Get Ethereum HDWallet from mnemonic phrase
    mnemonic=BIP39Mnemonic(
        mnemonic=BIP39Mnemonic.from_words(
            words=BIP39_MNEMONIC_WORDS.TWELVE,
            language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
        )
    )
).from_derivation(  # Drive from BIP44 derivation
    derivation=BIP44Derivation(
        coin_type=Cryptocurrency.COIN_TYPE,
        account=0,
        change=CHANGES.EXTERNAL_CHAIN,
        address=(0, 10)  # or "0-10"
    )
)

print("Mnemonic:", hdwallet.mnemonic())
print("Base HD Path:  m/44'/60'/0'/0/{address}", "\n")

# Print dived Ethereum HDWallet information's
for derivation in hdwallet.dumps(exclude={"root", "indexes"}):
    # Print path, address and private_key
    print(f"{derivation['at']['path']} {derivation['address']} 0x{derivation['private_key']}")
```

<details open>
  <summary>Output</summary><br/>

```shell script
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
Base HD Path:  m/44'/60'/0'/0/{address} 

m/44'/60'/0'/0/0 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727
m/44'/60'/0'/0/1 0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0 0x9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6
m/44'/60'/0'/0/2 0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A 0x5b824bd1104617939cd07c117ddc4301eb5beeca0904f964158963d69ab9d831
m/44'/60'/0'/0/3 0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E 0x9ffce93c14680776a0c319c76b4c25e7ad03bd780bf47f27ae9153324dcac585
m/44'/60'/0'/0/4 0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA 0xbd443149113127d73c350d0baeceedd2c83be3f10e3d57613a730649ddfaf0c0
m/44'/60'/0'/0/5 0xA40cFBFc8534FFC84E20a7d8bBC3729B26a35F6f 0x5a8787e6b7e11a74a22ee97b8164c7d69cd5668c6065bbfbc87e6a34a24b135c
m/44'/60'/0'/0/6 0xB191a13bfE648B61002F2e2135867015B71816a6 0x56e506258e5b0e3b6023b17941d84f8a13d655c525419b9ff0a52999a2c687a3
m/44'/60'/0'/0/7 0x593814d3309e2dF31D112824F0bb5aa7Cb0D7d47 0xdfb0930bcb8f6ca83296c1870e941998c641d3d0d413013c890b8b255dd537b5
m/44'/60'/0'/0/8 0xB14c391e2bf19E5a26941617ab546FA620A4f163 0x66014718190fedba55dc3f4709f6b5b34b9b1feebb110e7b87391054cbbffdd2
m/44'/60'/0'/0/9 0x4C1C56443AbFe6dD33de31dAaF0a6E929DBc4971 0x22fb8f2fe3b2dbf632bc5eb450a96ec56185733234f17e49c2483bb337ebf145
m/44'/60'/0'/0/10 0xEf4ba16373841C53a9Ba168873fC3967118C1d37 0x1d8e676c6da57922d80336cffc5bf9020d0cce4730cff872aeb2dcce08320ce6
```
</details>

[Phantom](https://github.com/phantom) wallet look's like:

```python
#!/usr/bin/env python3

from typing import Type

import json

from hdwallet.mnemonics import BIP39Mnemonic
from hdwallet.cryptocurrencies import (
    ICryptocurrency, Bitcoin, Ethereum, Solana
)
from hdwallet.hds import (
    IHD, BIP32HD, BIP44HD, BIP49HD, BIP84HD
)
from hdwallet.derivations import (
    IDerivation, CustomDerivation, BIP44Derivation, BIP49Derivation, BIP84Derivation
)
from hdwallet.const import PUBLIC_KEY_TYPES
from hdwallet.libs.base58 import encode
from hdwallet.utils import get_bytes
from hdwallet import HDWallet


mnemonic: BIP39Mnemonic = BIP39Mnemonic(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

# Phantom wallet standards
standards: dict = {
    "solana": {
        "hd": BIP32HD,
        "derivation": CustomDerivation(path=f"m/44'/{Solana.COIN_TYPE}'/0'/0'")
    },
    "ethereum": {
        "hd": BIP44HD,
        "derivation": BIP44Derivation(coin_type=Ethereum.COIN_TYPE)
    },
    "bitcoin": {
        "legacy": {
            "hd": BIP44HD,
            "derivation": BIP44Derivation(coin_type=Bitcoin.COIN_TYPE)
        },
        "nested-segwit": {
            "hd": BIP49HD,
            "derivation": BIP49Derivation(coin_type=Bitcoin.COIN_TYPE)
        },
        "native-segwit": {
            "hd": BIP84HD,
            "derivation": BIP84Derivation(coin_type=Bitcoin.COIN_TYPE)
        }
    }
}

def generate_phantom_hdwallet(cryptocurrency: Type[ICryptocurrency], hd: Type[IHD], network: str, derivation: IDerivation, **kwargs) -> HDWallet:
    return HDWallet(cryptocurrency=cryptocurrency, hd=hd, network=network, kwargs=kwargs).from_mnemonic(mnemonic=mnemonic).from_derivation(derivation=derivation)

print("Mnemonic:", mnemonic.mnemonic(), "\n")

# Solana
solana_hdwallet: HDWallet = generate_phantom_hdwallet(
    cryptocurrency=Solana,
    hd=standards["solana"]["hd"],
    network=Solana.NETWORKS.MAINNET,
    derivation=standards["solana"]["derivation"]
)
print(f"{solana_hdwallet.cryptocurrency()} ({solana_hdwallet.symbol()}) wallet:", json.dumps(dict(
    path=solana_hdwallet.path(),
    base58=encode(get_bytes(
        solana_hdwallet.private_key() + solana_hdwallet.public_key()[2:]
    )),
    private_key=solana_hdwallet.private_key(),
    public_key=solana_hdwallet.public_key()[2:],
    address=solana_hdwallet.address()
), indent=4))

# Ethereum
ethereum_hdwallet: HDWallet = generate_phantom_hdwallet(
    cryptocurrency=Ethereum,
    hd=standards["ethereum"]["hd"],
    network=Ethereum.NETWORKS.MAINNET,
    derivation=standards["ethereum"]["derivation"]
)
print(f"{ethereum_hdwallet.cryptocurrency()} ({ethereum_hdwallet.symbol()}) wallet:", json.dumps(dict(
    path=ethereum_hdwallet.path(),
    private_key=f"0x{ethereum_hdwallet.private_key()}",
    public_key=ethereum_hdwallet.public_key(),
    address=ethereum_hdwallet.address()
), indent=4))

# Bitcoin (Legacy, Nested-SegWit, Native-SegWit)
for address_type in ["legacy", "nested-segwit", "native-segwit"]:

    bitcoin_hdwallet: HDWallet = generate_phantom_hdwallet(
        cryptocurrency=Bitcoin,
        hd=standards["bitcoin"][address_type]["hd"],
        network=Bitcoin.NETWORKS.MAINNET,
        derivation=standards["bitcoin"][address_type]["derivation"],
        public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
    )
    print(f"{bitcoin_hdwallet.cryptocurrency()} ({bitcoin_hdwallet.symbol()}) {address_type.title()} wallet:", json.dumps(dict(
        path=bitcoin_hdwallet.path(),
        wif=bitcoin_hdwallet.wif(),
        private_key=bitcoin_hdwallet.private_key(),
        public_key=bitcoin_hdwallet.public_key(),
        address=bitcoin_hdwallet.address()
    ), indent=4))
```

<details open>
  <summary>Output</summary><br/>

```shell script
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about 

Solana (SOL) wallet: {
    "path": "m/44'/501'/0'/0'",
    "base58": "27npWoNE4HfmLeQo1TyWcW7NEA28qnsnDK7kcttDQEWrCWnro83HMJ97rMmpvYYZRwDAvG4KRuB7hTBacvwD7bgi",
    "private_key": "37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445",
    "public_key": "00f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
    "address": "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
}
Ethereum (ETH) wallet: {
    "path": "m/44'/60'/0'/0/0",
    "private_key": "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
    "public_key": "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
    "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
}
Bitcoin (BTC) Legacy wallet: {
    "path": "m/44'/0'/0'/0/0",
    "wif": "L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf",
    "private_key": "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
    "public_key": "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
    "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
}
Bitcoin (BTC) Nested-Segwit wallet: {
    "path": "m/49'/0'/0'/0/0",
    "wif": "KyvHbRLNXfXaHuZb3QRaeqA5wovkjg4RuUpFGCxdH5UWc1Foih9o",
    "private_key": "508c73a06f6b6c817238ba61be232f5080ea4616c54f94771156934666d38ee3",
    "public_key": "039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
    "address": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
}
Bitcoin (BTC) Native-Segwit wallet: {
    "path": "m/84'/0'/0'/0/0",
    "wif": "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
    "private_key": "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3",
    "public_key": "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
}
```
</details>

Explore more [Clients](https://github.com/hdwallet-io/python-hdwallet/blob/master/clients)

## Development

To get started, just fork this repo, clone it locally, and run:

```
pip install -e .[cli,tests,docs]
```

## Testing

You can run the tests with:

```
coverage run -m pytest
```

To see the coverage:

```
coverage report
```

Or use `tox` to run the complete suite against the full set of build targets, or pytest to run specific 
tests against a specific version of Python.

## Contributing

Feel free to open an [issue](https://github.com/hdwallet-io/python-hdwallet/issues) if you find a problem,
or a pull request if you've solved an issue. And also any help in testing, development,
documentation and other tasks is highly appreciated and useful to the project.
There are tasks for contributors of all experience levels.

For more information, see the [CONTRIBUTING.md](https://github.com/hdwallet-io/python-hdwallet/blob/master/CONTRIBUTING.md) file.

## Supported Cryptocurrencies

This library simplifies the process of creating a new Hierarchical Deterministic (HD) Wallet for:

| Name                                                                       | Symbol | Coin Type |             Networks             |          ECC           |                                         HDs                                         |       BIP38        |                                   Addresses                                   |
|:---------------------------------------------------------------------------|:------:|:---------:|:--------------------------------:|:----------------------:|:-----------------------------------------------------------------------------------:|:------------------:|:-----------------------------------------------------------------------------:|
| [Adcoin](https://github.com/adcoin-project/AdCoin)                         |  ACC   |    161    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Akash-Network](https://github.com/akash-network)                          |  AKT   |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Algorand](https://github.com/algorand/go-algorand)                        |  ALGO  |    283    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Algorand`                                   |
| [Anon](https://github.com/anonymousbitcoin/anon)                           |  ANON  |    220    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Aptos](https://github.com/aptos-labs)                                     |  APT   |    637    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Aptos`                                    |
| [Arbitrum](https://arbitrum.foundation)                                    |  ARB   |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Argoneum](https://github.com/Argoneum/argoneum)                           |  AGM   |    421    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Artax](https://github.com/artax-committee/Artax)                          |  XAX   |    219    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Aryacoin](https://github.com/Aryacoin/Aryacoin)                           |  AYA   |    357    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Asiacoin](http://www.thecoin.asia)                                        |   AC   |    51     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Auroracoin](https://github.com/aurarad/auroracoin)                        |  AUR   |    85     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Avalanche](https://github.com/ava-labs/avalanchego)                       |  AVAX  |   9000    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                            `Avalanche`, `Ethereum`                            |
| [Avian](https://github.com/AvianNetwork/Avian)                             |  AVN   |    921    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Axe](https://github.com/AXErunners/axe)                                   |  AXE   |   4242    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Axelar](https://github.com/axelarnetwork/axelar-core)                     |  AXL   |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Band-Protocol](https://github.com/bandprotocol/chain)                     |  BAND  |    494    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Bata](https://github.com/BTA-BATA/Bataoshi)                               |  BTA   |    89     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Beetle-Coin](https://github.com/beetledev/Wallet)                         |  BEET  |    800    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bela-Coin](https://github.com/TheAmbiaFund/erc20bela)                     |  BELA  |    73     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Binance](https://github.com/bnb-chain/bsc)                                |  BNB   |    714    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                             `Cosmos`, `Ethereum`                              |
| [Bit-Cloud](https://github.com/LIMXTEC/Bitcloud)                           |  BTDX  |    218    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bitcoin](https://github.com/bitcoin/bitcoin)                              |  BTC   |     0     | `mainnet`, `testnet`, `regtest`  |    SLIP10-Secp256k1    | `BIP32`, `BIP44`, `BIP49`, `BIP84`, `BIP86`, `BIP141`, `Electrum-V1`, `Electrum-V2` | :white_check_mark: | `P2PKH`, `P2SH`, `P2TR`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH` |
| [Bitcoin-Atom](https://github.com/bitcoin-atom/bitcoin-atom)               |  BCA   |    185    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Bitcoin-Cash](https://github.com/bitcoincashorg/bitcoincash.org)          |  BCH   |    145    | `mainnet`, `testnet`, `regtest`  |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Bitcoin-Cash-SLP](https://github.com/bitcoincashorg/bitcoincash.org)      |  SLP   |    145    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Bitcoin-Gold](https://github.com/BTCGPU/BTCGPU)                           |  BTG   |    156    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Bitcoin-Green](https://github.com/bitcoin-green/bitcoingreen)             |  BITG  |    222    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bitcoin-Plus](https://github.com/bitcoinplusorg/xbcwalletsource)          |  XBC   |    65     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bitcoin-Private](https://github.com/BTCPrivate/BitcoinPrivate)            |  BTCP  |    183    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bitcoin-SV](https://github.com/bitcoin-sv/bitcoin-sv)                     |  BSV   |    236    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [BitcoinZ](https://github.com/btcz/bitcoinz)                               |  BTCZ  |    177    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Bitcore](https://github.com/bitcore-btx/BitCore)                          |  BTX   |    160    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Bit-Send](https://github.com/LIMXTEC/BitSend)                             |  BSD   |    91     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Blackcoin](https://github.com/coinblack)                                  |  BLK   |    10     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Blocknode](https://github.com/blocknodetech/blocknode)                    |  BND   |   2941    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Block-Stamp](https://github.com/BlockStamp)                               |  BST   |    254    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Bolivarcoin](https://github.com/BOLI-Project/BolivarCoin)                 |  BOLI  |    278    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Brit-Coin](https://github.com/britcoin3)                                  |  BRIT  |    70     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Canada-eCoin](https://github.com/Canada-eCoin)                            |  CDN   |    34     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Cannacoin](https://github.com/cannacoin-official/Cannacoin)               |  CCN   |    19     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Cardano](https://cardanoupdates.com)                                      |  ADA   |   1815    |       `mainnet`, `testnet`       |     Kholaw-Ed25519     |                                      `Cardano`                                      |        :x:         |                                   `Cardano`                                   |
| [Celo](https://github.com/celo-org/celo-monorepo)                          |  CELO  |   52752   |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Chihuahua](http://chihuahua.army)                                         |  HUA   |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Clams](https://github.com/nochowderforyou/clams)                          |  CLAM  |    23     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Club-Coin](https://github.com/BitClubDev/ClubCoin)                        |  CLUB  |    79     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Compcoin](https://compcoin.com)                                           |  CMP   |    71     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Cosmos](https://github.com/cosmos)                                        |  ATOM  |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [CPU-Chain](https://github.com/cpuchain/cpuchain)                          |  CPU   |    363    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Crane-Pay](https://github.com/cranepay/cranepay-core)                     |  CRP   |   2304    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Crave](https://github.com/Crave-Community-Project/Crave-Project)          | CRAVE  |    186    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Dash](https://github.com/dashpay/dash)                                    |  DASH  |     5     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [DeepOnion](https://github.com/deeponion/deeponion)                        | ONION  |    305    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Defcoin](https://github.com/mspicer/Defcoin)                              |  DFC   |   1337    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Denarius](https://github.com/metaspartan/denarius)                        |  DNR   |    116    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Diamond](https://github.com/DMDcoin/Diamond)                              |  DMD   |    152    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Digi-Byte](https://github.com/DigiByte-Core/digibyte)                     |  DGB   |    20     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Digitalcoin](https://github.com/lomtax/digitalcoin)                       |  DGC   |    18     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Divi](https://github.com/Divicoin/Divi)                                   |  DIVI  |    301    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Dogecoin](https://github.com/dogecoin/dogecoin)                           |  DOGE  |     3     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [dYdX](https://github.com/dydxprotocol)                                    |  DYDX  | 22000118  |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [eCash](https://github.com/bitcoin-abc)                                    |  XEC   |    145    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [E-coin](https://github.com/ecoinclub/ecoin)                               |  ECN   |    115    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [EDR-Coin](https://github.com/EDRCoin/EDRcoin-src)                         |  EDRC  |    56     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [e-Gulden](https://github.com/Electronic-Gulden-Foundation/egulden)        |  EFL   |    78     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Einsteinium](https://github.com/emc2foundation/einsteinium)               |  EMC2  |    41     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Elastos](https://github.com/elastos)                                      |  ELA   |   2305    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Energi](https://github.com/energicryptocurrency/go-energi)                |  NRG   |   9797    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [EOS](https://github.com/AntelopeIO/leap)                                  |  EOS   |    194    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                     `EOS`                                     |
| [Ergo](https://github.com/ergoplatform/ergo)                               |  ERG   |    429    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Ergo`                                     |
| [Ethereum](https://github.com/ethereum/go-ethereum)                        |  ETH   |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Europe-Coin](https://github.com/LIMXTEC/Europecoin-V3)                    |  ERC   |    151    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Evrmore](https://github.com/EvrmoreOrg/Evrmore)                           |  EVR   |    175    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Exclusive-Coin](https://github.com/exclfork/excl-core)                    |  EXCL  |    190    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Fantom](https://github.com/Fantom-foundation/go-opera)                    |  FTM   |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Feathercoin](https://github.com/FeatherCoin/Feathercoin)                  |  FTC   |     8     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Fetch.ai](https://github.com/fetchai)                                     |  FET   |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Filecoin](https://github.com/filecoin-project)                            |  FIL   |    461    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Filecoin`                                   |
| [Firo](https://github.com/firoorg/firo)                                    |  FIRO  |    136    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Firstcoin](http://firstcoinproject.com)                                   |  FRST  |    167    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [FIX](https://github.com/NewCapital/FIX-Core)                              |  FIX   |    336    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Flashcoin](https://github.com/flash-coin)                                 | FLASH  |    120    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Flux](https://github.com/RunOnFlux/fluxd)                                 |  FLUX  |   19167   |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Foxdcoin](https://github.com/foxdproject/foxdcoin)                        |  FOXD  |    175    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Fuji-Coin](https://github.com/fujicoin/fujicoin)                          |  FJC   |    75     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Game-Credits](https://github.com/gamecredits-project/GameCredits)         |  GAME  |    101    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [GCR-Coin](https://globalcoinresearch.com)                                 |  GCR   |    49     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Go-Byte](https://github.com/gobytecoin/gobyte)                            |  GBX   |    176    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Gridcoin](https://github.com/gridcoin-community/Gridcoin-Research)        |  GRC   |    84     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Groestl-Coin](https://github.com/Groestlcoin/groestlcoin)                 |  GRS   |    17     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Gulden](https://github.com/Gulden/gulden-old)                             |  NLG   |    87     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Harmony](https://github.com/harmony-one/harmony)                          |  ONE   |   1023    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Harmony`                                   |
| [Helleniccoin](https://github.com/hnc-coin/hnc-coin)                       |  HNC   |    168    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Hempcoin](https://github.com/jl777/komodo)                                |  THC   |    113    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Horizen](https://github.com/HorizenOfficial/zen)                          |  ZEN   |    121    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Huobi-Token](https://www.huobi.com/en-us)                                 |   HT   |    553    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Hush](https://git.hush.is/hush/hush3)                                     |  HUSH  |    197    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Icon](https://github.com/icon-project)                                    |  ICX   |    74     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Icon`                                     |
| [Injective](https://github.com/InjectiveLabs)                              |  INJ   |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Injective`                                  |
| [InsaneCoin](https://github.com/CryptoCoderz/INSN)                         |  INSN  |    68     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Internet-Of-People](https://github.com/Internet-of-People)                |  IOP   |    66     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [IRISnet](https://github.com/irisnet)                                      |  IRIS  |    566    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [IX-Coin](https://github.com/ixcore/ixcoin)                                |  IXC   |    86     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Jumbucks](http://getjumbucks.com)                                         |  JBS   |    26     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Kava](https://github.com/kava-labs)                                       |  KAVA  |    459    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Kobocoin](https://github.com/kobocoin/Kobocoin)                           |  KOBO  |    196    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Komodo](https://github.com/KomodoPlatform/komodo)                         |  KMD   |    141    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Landcoin](http://landcoin.co)                                             |  LDCN  |    63     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [LBRY-Credits](https://github.com/lbryio/lbrycrd)                          |  LBC   |    140    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Linx](https://github.com/linX-project/linX)                               |  LINX  |    114    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Litecoin](https://github.com/litecoin-project/litecoin)                   |  LTC   |     2     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                              `BIP84`, `BIP44`, `BIP32`                              | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Litecoin-Cash](https://github.com/litecoincash-project/litecoincash)      |  LCC   |    192    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [LitecoinZ](https://github.com/litecoinz-project/litecoinz)                |  LTZ   |    221    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Lkrcoin](https://github.com/LKRcoin/lkrcoin)                              |  LKR   |    557    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Lynx](https://github.com/doh9Xiet7weesh9va9th/lynx)                       |  LYNX  |    191    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Mazacoin](https://github.com/MazaCoin/maza)                               |  MZC   |    13     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Megacoin](https://github.com/LIMXTEC/Megacoin)                            |  MEC   |    217    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Metis](https://github.com/MetisProtocol/metis)                            | METIS  |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Minexcoin](https://github.com/minexcoin/minexcoin)                        |  MNX   |    182    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Monacoin](https://github.com/monacoinproject/monacoin)                    |  MONA  |    22     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Monero](https://github.com/monero-project/monero)                         |  XMR   |    128    | `mainnet`, `stagenet`, `testnet` | SLIP10-Ed25519-Monero  |                                      `Monero`                                       |        :x:         |                                   `Monero`                                    |
| [Monk](https://github.com/decenomy/MONK)                                   |  MONK  |    214    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [MultiversX](https://github.com/multiversx/mx-chain-go)                    |  EGLD  |    508    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                 `MultiversX`                                  |
| [Myriadcoin](https://github.com/myriadteam/myriadcoin)                     |  XMY   |    90     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Namecoin](https://github.com/namecoin/namecoin-core)                      |  NMC   |     7     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Nano](https://github.com/nanocurrency/nano-node)                          |  XNO   |    165    |            `mainnet`             | SLIP10-Ed25519-Blake2b |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Nano`                                     |
| [Navcoin](https://github.com/navcoin/navcoin-core)                         |  NAV   |    130    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Near](https://github.com/near/nearcore)                                   |  NEAR  |    397    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Near`                                     |
| [Neblio](https://github.com/NeblioTeam/neblio)                             |  NEBL  |    146    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Neo](https://github.com/neo-project/neo)                                  |  NEO   |    888    |            `mainnet`             |    SLIP10-Nist256p1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                     `Neo`                                     |
| [Neoscoin](http://www.getneos.com)                                         |  NEOS  |    25     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Neurocoin](https://github.com/neurocoin/neurocoin)                        |  NRO   |    110    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Neutron](https://github.com/neutron-org)                                  |  NTRN  |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [New-York-Coin](https://github.com/NewYorkCoinNYC/newyorkcoin)             |  NYC   |    179    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Nine-Chronicles](https://github.com/planetarium/NineChronicles)           |  NCG   |    567    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [NIX](https://github.com/NixPlatform/NixCore)                              |  NIX   |    400    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Novacoin](https://github.com/novacoin-project/novacoin)                   |  NVC   |    50     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [NuBits](https://bitbucket.org/NuNetwork/nubits)                           |  NBT   |    12     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [NuShares](https://bitbucket.org/JordanLeePeershares/nubit/overview)       |  NSR   |    11     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [OK-Cash](https://github.com/okcashpro/okcash)                             |   OK   |    69     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [OKT-Chain](https://github.com/okex/okexchain)                             |  OKT   |    996    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `OKT-Chain`                                  |
| [Omni](https://github.com/omnilayer/omnicore)                              |  OMNI  |    200    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Onix](https://github.com/onix-project)                                    |  ONX   |    174    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ontology](https://github.com/ontio/ontology)                              |  ONT   |   1024    |            `mainnet`             |    SLIP10-Nist256p1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                     `Neo`                                     |
| [Optimism](https://github.com/ethereum-optimism)                           |   OP   |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Osmosis](https://github.com/osmosis-labs/osmosis)                         |  OSMO  | 10000118  |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Particl](https://github.com/particl/particl-core)                         |  PART  |    44     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Peercoin](https://github.com/peercoin/peercoin)                           |  PPC   |     6     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Pesobit](https://github.com/pesobitph/pesobit-source)                     |  PSB   |    62     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Phore](https://github.com/phoreproject/Phore)                             |  PHR   |    444    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Pi-Network](https://github.com/pi-apps)                                   |   PI   |  314159   |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Stellar`                                   |
| [Pinkcoin](https://github.com/Pink2Dev/Pink2)                              |  PINK  |    117    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Pivx](https://github.com/PIVX-Project/PIVX)                               |  PIVX  |    119    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Polygon](https://github.com/maticnetwork/whitepaper)                      | MATIC  |    60     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [PoSW-Coin](https://posw.io)                                               |  POSW  |    47     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Potcoin](https://github.com/potcoin/Potcoin)                              |  POT   |    81     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Project-Coin](https://github.com/projectcoincore/ProjectCoin)             |  PRJ   |    533    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Putincoin](https://github.com/PutinCoinPUT/PutinCoin)                     |  PUT   |    122    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Qtum](https://github.com/qtumproject/qtum)                                |  QTUM  |   2301    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                `BIP84`, `BIP141`, `BIP32`, `BIP86`, `BIP44`, `BIP49`                | :white_check_mark: | `P2PKH`, `P2SH`, `P2TR`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH` |
| [Rapids](https://github.com/RapidsOfficial/Rapids)                         |  RPD   |    320    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ravencoin](https://github.com/RavenProject/Ravencoin)                     |  RVN   |    175    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP32`, `BIP44`                                   | :white_check_mark: |     `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`     |
| [Reddcoin](https://github.com/reddcoin-project/reddcoin)                   |  RDD   |     4     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ripple](https://github.com/ripple/rippled)                                |  XRP   |    144    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ritocoin](https://github.com/RitoProject/Ritocoin)                        |  RITO  |   19169   |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [RSK](https://github.com/rsksmart)                                         |  RBTC  |    137    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Rubycoin](https://github.com/rubycoinorg/rubycoin)                        |  RBY   |    16     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Safecoin](https://github.com/Fair-Exchange/safecoin)                      |  SAFE  |   19165   |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Saluscoin](https://github.com/saluscoin/SaluS)                            |  SLS   |    572    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Scribe](https://github.com/scribenetwork/scribe)                          | SCRIBE |    545    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Secret](https://github.com/scrtlabs/SecretNetwork)                        |  SCRT  |    529    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Shadow-Cash](https://github.com/shadowproject/shadow)                     |  SDC   |    35     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Shentu](https://github.com/ShentuChain)                                   |  CTK   |    118    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Slimcoin](https://github.com/slimcoin-project/Slimcoin)                   |  SLM   |    63     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Smileycoin](https://github.com/tutor-web/)                                |  SMLY  |    59     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Solana](https://github.com/solana-labs/solana)                            |  SOL   |    501    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Solana`                                    |
| [Solarcoin](https://github.com/onsightit/solarcoin)                        |  SLR   |    58     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Stafi](https://github.com/stafiprotocol/stafi-node)                       |  FIS   |    907    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Stash](https://docs.stash.capital)                                        | STASH  |   49344   |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Stellar](https://github.com/stellar/stellar-core)                         |  XLM   |    148    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Stellar`                                   |
| [Stratis](https://github.com/stratisproject)                               | STRAT  |    105    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Sugarchain](https://github.com/sugarchain-project/sugarchain)             | SUGAR  |    408    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Sui](https://github.com/MystenLabs/sui)                                   |  SUI   |    784    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                     `Sui`                                     |
| [Syscoin](https://github.com/syscoin/syscoin)                              |  SYS   |    57     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Terra](https://github.com/terra-money/core)                               |  LUNA  |    330    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Cosmos`                                    |
| [Tezos](https://github.com/tezos/tezos)                                    |  XTZ   |   1729    |            `mainnet`             |     SLIP10-Ed25519     |                                  `BIP44`, `BIP32`                                   |        :x:         |                                    `Tezos`                                    |
| [Theta](https://github.com/thetatoken)                                     | THETA  |    500    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Thought-AI](https://github.com/thoughtnetwork)                            |  THT   |    502    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [TOA-Coin](https://github.com/toacoin/TOA)                                 |  TOA   |    159    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Tron](https://github.com/tronprotocol/java-tron)                          |  TRX   |    195    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                `P2PKH`, `P2SH`                                |
| [TWINS](https://github.com/NewCapital/TWINS-Core)                          | TWINS  |    970    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ultimate-Secure-Cash](https://github.com/SilentTrader/UltimateSecureCash) |  USC   |    112    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Unobtanium](https://github.com/unobtanium-official/Unobtanium)            |  UNO   |    92     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Vcash](https://vcash.finance)                                             |   VC   |    127    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [VeChain](https://github.com/vechain)                                      |  VET   |    818    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                  `Ethereum`                                   |
| [Verge](https://github.com/vergecurrency/verge)                            |  XVG   |    77     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Vertcoin](https://github.com/vertcoin/vertcoin)                           |  VTC   |    28     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Viacoin](https://github.com/viacoin/viacoin)                              |  VIA   |    14     |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                  `P2PKH`, `P2SH`, `P2WPKH`, `P2WPKH-In-P2SH`                  |
| [Vivo](https://github.com/vivocoin/vivo)                                   |  VIVO  |    166    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Voxels](http://revolutionvr.live)                                         |  VOX   |    129    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Virtual-Cash](https://github.com/Bit-Net/vash)                            |  VASH  |    33     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Wagerr](https://github.com/wagerr/wagerr)                                 |  WGR   |     0     |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Whitecoin](https://github.com/Whitecoin-XWC/Whitecoin-core)               |  XWC   |    559    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Wincoin](https://github.com/Wincoinofficial/wincoin)                      |   WC   |    181    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [XinFin](https://github.com/XinFinOrg/XDPoSChain)                          |  XDC   |    550    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `XinFin`                                    |
| [XUEZ](https://github.com/XUEZ/Xuez-Core)                                  |  XUEZ  |    225    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Ycash](https://github.com/ycashfoundation/ycash)                          |  YEC   |    347    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Zcash](https://github.com/zcash/zcash)                                    |  ZEC   |    133    |       `mainnet`, `testnet`       |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [ZClassic](https://github.com/ZClassicCommunity/zclassic)                  |  ZCL   |    147    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Zetacoin](https://github.com/zetacoin/zetacoin)                           |  ZET   |    719    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |
| [Zilliqa](https://github.com/Zilliqa/Zilliqa)                              |  ZIL   |    313    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   |        :x:         |                                   `Zilliqa`                                   |
| [ZooBC](https://github.com/zoobc/zoobc-core)                               |  ZBC   |    883    |            `mainnet`             |    SLIP10-Secp256k1    |                                  `BIP44`, `BIP32`                                   | :white_check_mark: |                                `P2PKH`, `P2SH`                                |

## Donations

If this tool was helpful, support its development with a donation or a ⭐!

- **Bitcoin**: `16c7ajUwHEMaafrceuYSrd35SDjmfVdjoS`
- **Ethereum / ERC20**: `0xD3cbCB0B6F82A03C715D665b72dC44CEf54e6D9B`
- **Monero**: `47xYi7dw4VchWhbhacY6RZHDmmcxZdzPE9tLk84c7hE72bw6aLSMVFWPXxGMEEYofkjNjxoWfnLSHejS6yzRGnPqEtxfgZi`

We accept a wide range of cryptocurrencies! If you'd like to donate using another coin, generate an address using the following ECC public keys at [hdwallet.online](https://hdwallet.online):

| **ECC**                |                            **Public Key**                            |                                                                                                                                                               **Generate**                                                                                                                                                               |
|------------------------|:--------------------------------------------------------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| SLIP10-Secp256k1       | `029890465120fb6c4efecdfcfd149f8333b0929b98976722a28ee39f5344d29eee` |                                         [addresses](https://hdwallet.online/dumps/slip10-secp256k1/BTC?network=mainnet&hd=BIP32&from=public-key&public-key=029890465120fb6c4efecdfcfd149f8333b0929b98976722a28ee39f5344d29eee&public-key-type=compressed&format=JSON&exclude=root&generate=true)                                         |
| SLIP10-Ed25519         | `007ff5643c73e46e6c6a0dfd702894610505423e145dc8a93df19ff44eb011323b` |                                                       [addresses](https://hdwallet.online/dumps/slip10-ed25519/ALGO?network=mainnet&hd=BIP32&from=public-key&public-key=007ff5643c73e46e6c6a0dfd702894610505423e145dc8a93df19ff44eb011323b&format=JSON&exclude=root&generate=true)                                                       |
| Kholaw-Ed25519         | `005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3` | [addresses](https://hdwallet.online/dumps/kholaw-ed25519/ADA?network=mainnet&hd=Cardano&from=public-key&public-key=005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3&staking-public-key=005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3&address-type=payment&format=JSON&exclude=root&generate=true) |
| SLIP10-Ed25519-Blake2b | `0051e8b29f7d0214dc96843cdbdcc071dc65397016ea6f7381f81bf42d76c7357c` |                                                   [addresses](https://hdwallet.online/dumps/slip10-ed25519-blake2b/XNO?network=mainnet&hd=BIP32&from=public-key&public-key=0051e8b29f7d0214dc96843cdbdcc071dc65397016ea6f7381f81bf42d76c7357c&format=JSON&exclude=root&generate=true)                                                    |
| SLIP10-Nist256p1       | `039ee4e2aadd6f4e7938d164b646c4b424114b8dd57252287151398ba0baf25780` |                                                      [addresses](https://hdwallet.online/dumps/slip10-nist256p1/NEO?network=mainnet&hd=BIP32&from=public-key&public-key=039ee4e2aadd6f4e7938d164b646c4b424114b8dd57252287151398ba0baf25780&format=JSON&exclude=root&generate=true)                                                       |

## License

Distributed under the [MIT](https://github.com/hdwallet-io/python-hdwallet/blob/master/LICENSE) license. See ``LICENSE`` for more information.
