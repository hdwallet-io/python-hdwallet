# Hierarchical Deterministic (HD) Wallet

[![Build Status](https://img.shields.io/github/actions/workflow/status/hdwallet-io/python-hdwallet/build.yml)](https://github.com/hdwallet-io/python-hdwallet/actions/workflows/build.yml)
[![PyPI Version](https://img.shields.io/pypi/v/hdwallet.svg?color=blue)](https://pypi.org/project/hdwallet)
[![Documentation Status](https://readthedocs.org/projects/hdwallet/badge/?version=master)](https://hdwallet.readthedocs.io)
[![PyPI License](https://img.shields.io/pypi/l/hdwallet?color=black)](https://pypi.org/project/hdwallet)
[![PyPI Python Version](https://img.shields.io/pypi/pyversions/hdwallet.svg)](https://pypi.org/project/hdwallet)
[![Coverage Status](https://coveralls.io/repos/github/hdwallet-io/python-hdwallet/badge.svg?branch=master)](https://coveralls.io/github/hdwallet-io/python-hdwallet)

Python-based library implementing a Hierarchical Deterministic (HD) Wallet generator for 200+ cryptocurrencies.

> This library offers a flexible and scalable solution for developers integrating multi-currency wallet functionality. It adheres to standard protocols for compatibility with other wallets and services, and provides features like secure seed generation, robust key management, and streamlined account control. By simplifying blockchain interactions, it enhances the developer experience and strengthens end-user security.
> 
> For TypeScript/JavaScript support, explore [hdwallet.js](https://github.com/hdwallet-io/hdwallet.js), the official port of this library. Try it live at https://hdwallet.online, our interactive web playground.

| Features                      | Protocols                                                                                                                                                                                                                                                                                                                                           |
|:------------------------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Cryptocurrencies              | <a href="https://hdwallet.io/cryptocurrencies">#supported-cryptocurrencies</a>                                                                                                                                                                                                                                                                      |
| Entropies                     | `Algorand`, `BIP39`, `SLIP39`, `Electrum-V1`, `Electrum-V2`, `Monero`                                                                                                                                                                                                                                                                               |
| Mnemonics                     | `Algorand`, `BIP39`, `SLIP39`, `Electrum-V1`, `Electrum-V2`, `Monero`                                                                                                                                                                                                                                                                               |
| Seeds                         | `Algorand`, `BIP39`, `SLIP39`, `Cardano`, `Electrum-V1`, `Electrum-V2`, `Monero`                                                                                                                                                                                                                                                                    |
| Elliptic Curve Cryptography's | `Kholaw-Ed25519`, `SLIP10-Ed25519`, `SLIP10-Ed25519-Blake2b`, `SLIP10-Ed25519-Monero`, `SLIP10-Nist256p1`, `SLIP10-Secp256k1`                                                                                                                                                                                                                       |
| Hierarchical Deterministic's  | `Algorand`, `BIP32`, `BIP44`, `BIP49`, `BIP84`, `BIP86`, `BIP141`, `Cardano`, `Electrum-V1`, `Electrum-V2`, `Monero`                                                                                                                                                                                                                                |
| Derivations                   | `BIP44`, `BIP49`, `BIP84`, `BIP86`, `CIP1852`, `Custom`, `Electrum`, `Monero`, `HDW (Our own custom derivation)`                                                                                                                                                                                                                                    |
| Addresses                     | `Algorand`, `Aptos`, `Avalanche`, `Cardano`, `Cosmos`, `EOS`, `Ergo`, `Ethereum`, `Filecoin`, `Harmony`, `Icon`, `Injective`, `Monero`, `MultiversX`, `Nano`, `Near`, `Neo`, `OKT-Chain`, `P2PKH`, `P2SH`, `P2TR`, `P2WPKH`, `P2WPKH-In-P2SH`, `P2WSH`, `P2WSH-In-P2SH`, `Ripple`, `Solana`, `Stellar`, `Sui`, `Tezos`, `Tron`, `XinFin`, `Zilliqa` |
| Others                        | `BIP38`, `Wallet Import Format`, `Serialization`                                                                                                                                                                                                                                                                                                    |

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
from hdwallet.consts import PUBLIC_KEY_TYPES

import json

hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP32HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    language=BIP39_MNEMONIC_LANGUAGES.KOREAN,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    passphrase="talonlab"
).from_entropy(
    entropy=BIP39Entropy(
        entropy=BIP39Entropy.generate(
            strength=BIP39_ENTROPY_STRENGTHS.ONE_HUNDRED_TWENTY_EIGHT
        )
    )
).from_derivation(
    derivation=CustomDerivation(
        path="m/0'/0/0-1"  # Cryptocurrency.DEFAULT_PATH
    )
)

# print(json.dumps(hdwallet.dump(exclude={"indexes"}), indent=4, ensure_ascii=False))  # dump
print(json.dumps(hdwallet.dumps(exclude={"indexes"}), indent=4, ensure_ascii=False))  # dumps
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
    "passphrase": "talonlab",
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
    "derivations": [
        {
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
        },
        {
            "at": {
                "path": "m/0'/0/1",
                "depth": 3,
                "index": 1
            },
            "xprivate_key": "xprv9ygweU6CCkHDmj3unNmBaXknTsrh9jzuY1acX2GQZ3pDrFMM4uskpf7CciYNKnXxs9YfDD173rxoCpErE3HzcNP5NSDhyKqtEoRW3wgd9ap",
            "xpublic_key": "xpub6CgJ3yd637qWzD8NtQJBwfhX1uhBZCikuEWDKQg27PMCj3gVcTC1NTRgU2Rdzzu9oS4tDnG2yNNmtmpDjo2XaUHFaNxSaJGUGimCq9pz4ma",
            "private_key": "408d26ffd1054c1bf670b9eb4596927a5a514e776a96c1207545b24164a39b3b",
            "wif": "KyPBzVhKq61epwjd8MokmKVT41yK35138HJkMHzSsj1DSDZ29RqH",
            "chain_code": "76cf29a3ec5cd3ff80042841729650ea0233c546996da51e9bc2aa55aeae0a3a",
            "public_key": "03b85939956927999c277753b088b79051a9b310bdf8bb5133b19e9d6afde53a2d",
            "uncompressed": "04b85939956927999c277753b088b79051a9b310bdf8bb5133b19e9d6afde53a2d916877edeca0bd2af66974947301610d672a706cf14ae52a42903670c002d6a1",
            "compressed": "03b85939956927999c277753b088b79051a9b310bdf8bb5133b19e9d6afde53a2d",
            "hash": "2bcd7323743e0ad9b51a23c9c26ec665da7c4031",
            "fingerprint": "2bcd7323",
            "parent_fingerprint": "8ba1670b",
            "addresses": {
                "p2pkh": "14zcB9bnKS86bPJWhbnkcvJE9RGFmM2TGq",
                "p2sh": "3LtKCT6Bgnrb9KPqxeMjztQSDhFM9p3B8A",
                "p2tr": "bc1p9tz8fvm389nmfg73pkw0ee4rxtdvg82mpt489rhunv5lys450htsjc4vtq",
                "p2wpkh": "bc1q90xhxgm58c9dndg6y0yuymkxvhd8csp32lpnzt",
                "p2wpkh_in_p2sh": "3QZdMy6k1aq5sZeSuGiv1gD7ec45mk4t87",
                "p2wsh": "bc1q36u54nlxk5vjpaynus04qlxrgntcyl6dl3p7vecn3xj37cqjphqsfvjjh4",
                "p2wsh_in_p2sh": "34BsDYDWzfC8D1HbVDtzRniW9ASwxT86KP"
            }
        }
    ]
}
```
</details>

Explore more [Examples](https://github.com/hdwallet-io/python-hdwallet/blob/master/examples)

### Command Line Interface (CLI)

The `hdwallet` CLI provides a simple way to generate wallets, derive addresses, and manage keys directly from your terminal, with options for exporting data in JSON and CSV formats. 

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

hdwallet: HDWallet = HDWallet(
    cryptocurrency=Cryptocurrency,
    hd=BIP44HD,
    network=Cryptocurrency.NETWORKS.MAINNET,
    passphrase=None
).from_mnemonic(
    mnemonic=BIP39Mnemonic(
        mnemonic=BIP39Mnemonic.from_words(
            words=BIP39_MNEMONIC_WORDS.TWELVE,
            language=BIP39_MNEMONIC_LANGUAGES.ENGLISH
        )
    )
).from_derivation(
    derivation=BIP44Derivation(
        coin_type=Cryptocurrency.COIN_TYPE,
        account=0,
        change=CHANGES.EXTERNAL_CHAIN,
        address=(0, 10)  # or "0-10"
    )
)

print("Mnemonic:", hdwallet.mnemonic())
print("Base HD Path:  m/44'/60'/0'/0/{address}", "\n")

for derivation in hdwallet.dumps(exclude={"root", "indexes"}):
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

from hdwallet import HDWallet
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
from hdwallet.consts import PUBLIC_KEY_TYPES
from hdwallet.libs.base58 import encode
from hdwallet.utils import get_bytes


mnemonic: BIP39Mnemonic = BIP39Mnemonic(
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

standards: dict = {
    "solana": {
        "hd": BIP32HD,
        "derivation": CustomDerivation(path=Solana.DEFAULT_PATH)
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

for address_type in ["legacy", "nested-segwit", "native-segwit"]:

    bitcoin_hdwallet: HDWallet = generate_phantom_hdwallet(
        cryptocurrency=Bitcoin,
        hd=standards["bitcoin"][address_type]["hd"],
        network=Bitcoin.NETWORKS.MAINNET,
        derivation=standards["bitcoin"][address_type]["derivation"],
        public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
    )
    print(f"{bitcoin_hdwallet.cryptocurrency()} ({bitcoin_hdwallet.symbol()}) {address_type} wallet:", json.dumps(dict(
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
    "public_key": "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7",
    "address": "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
}
Ethereum (ETH) wallet: {
    "path": "m/44'/60'/0'/0/0",
    "private_key": "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
    "public_key": "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299",
    "address": "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
}
Bitcoin (BTC) legacy wallet: {
    "path": "m/44'/0'/0'/0/0",
    "wif": "L4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf",
    "private_key": "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
    "public_key": "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
    "address": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
}
Bitcoin (BTC) nested-segwit wallet: {
    "path": "m/49'/0'/0'/0/0",
    "wif": "KyvHbRLNXfXaHuZb3QRaeqA5wovkjg4RuUpFGCxdH5UWc1Foih9o",
    "private_key": "508c73a06f6b6c817238ba61be232f5080ea4616c54f94771156934666d38ee3",
    "public_key": "039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
    "address": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
}
Bitcoin (BTC) native-segwit wallet: {
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

## Donations

If this tool was helpful, support its development with a donation or a ⭐!

- **Monero**: `47xYi7dw4VchWhbhacY6RZHDmmcxZdzPE9tLk84c7hE72bw6aLSMVFWPXxGMEEYofkjNjxoWfnLSHejS6yzRGnPqEtxfgZi`
- **EVM-Chains**: `0xD3cbCB0B6F82A03C715D665b72dC44CEf54e6D9B` | `meherett.eth`
- **Bitcoin**: `16c7ajUwHEMaafrceuYSrd35SDjmfVdjoS`

> [!TIP]
> We accept a wide range of cryptocurrencies! If you'd like to donate using another coin, generate an address using the following ECC public keys at [https://hdwallet.online](https://hdwallet.online):
>
> - **SLIP10-Secp256k1**: [029890465120fb6c4efecdfcfd149f8333b0929b98976722a28ee39f5344d29eee](https://hdwallet.online/dumps/slip10-secp256k1/BTC?network=mainnet&hd=BIP32&from=public-key&public-key=029890465120fb6c4efecdfcfd149f8333b0929b98976722a28ee39f5344d29eee&public-key-type=compressed&format=JSON&exclude=root&generate=true)                                         
> - **SLIP10-Ed25519**: [007ff5643c73e46e6c6a0dfd702894610505423e145dc8a93df19ff44eb011323b](https://hdwallet.online/dumps/slip10-ed25519/ALGO?network=mainnet&hd=BIP32&from=public-key&public-key=007ff5643c73e46e6c6a0dfd702894610505423e145dc8a93df19ff44eb011323b&format=JSON&exclude=root&generate=true)                                                       
> - **Kholaw-Ed25519**: [005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3](https://hdwallet.online/dumps/kholaw-ed25519/ADA?network=mainnet&hd=Cardano&from=public-key&public-key=005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3&staking-public-key=005a49188ccd3d841dd877d7c00078da5c90452cbd69d4cef7a959f679fcc0e0e3&address-type=payment&format=JSON&exclude=root&generate=true) 
> - **SLIP10-Ed25519-Blake2b**: [0051e8b29f7d0214dc96843cdbdcc071dc65397016ea6f7381f81bf42d76c7357c](https://hdwallet.online/dumps/slip10-ed25519-blake2b/XNO?network=mainnet&hd=BIP32&from=public-key&public-key=0051e8b29f7d0214dc96843cdbdcc071dc65397016ea6f7381f81bf42d76c7357c&format=JSON&exclude=root&generate=true)                                                    
> - **SLIP10-Nist256p1**: [039ee4e2aadd6f4e7938d164b646c4b424114b8dd57252287151398ba0baf25780](https://hdwallet.online/dumps/slip10-nist256p1/NEO?network=mainnet&hd=BIP32&from=public-key&public-key=039ee4e2aadd6f4e7938d164b646c4b424114b8dd57252287151398ba0baf25780&format=JSON&exclude=root&generate=true)                                                       

## License

Distributed under the [MIT](https://github.com/hdwallet-io/python-hdwallet/blob/master/LICENSE) license. See `LICENSE` for more information.
