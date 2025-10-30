# Changelog

## [v3.7.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.7.0) (2025-08-20)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.6.1...v3.7.0)

**New Additions:**

- Add: SLIP-39 mnemonic and seed support with multi-language wordlist handling
- Add: Raw entropy support for SLIP-39 seeds

**Enhancements:**

- Improve: SLIP-39 mnemonic implementation and multi-mnemonic handling

## [v3.6.1](https://github.com/hdwallet-io/python-hdwallet/tree/v3.6.1) (2025-08-04)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.6.0...v3.6.1)

**Enhancements:**

- Update: retrieve ECC name from HD class in HDWallet

**Fix Bugs:**

- Fix: parent-fingerprint of AlgorandHD implementation

## [v3.6.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.6.0) (2025-07-31)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.5.1...v3.6.0)

**New Cryptocurrencies:**

| Name                     | Symbol | Coin Type | Networks  |
|:-------------------------|:------:|:---------:|:---------:|
| [Base](https://base.org) |  BASE  |    60     | `mainnet` |

**New Additions:**

- Add: Algorand foundation xHD (AlgorandHD) implementation

**Enhancements:**

- Modify: BIP32 HD to accept custom ECC on HDWallet class
- Change: default Algorand cryptocurrency ECC to `Kholaw-Ed25519`

## [v3.5.1](https://github.com/hdwallet-io/python-hdwallet/tree/v3.5.1) (2025-07-20)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.4.0...v3.5.1)

**New Additions:**

- Add: `SEMANTICS`, `DEFAULT_SEMANTIC`, `DEFAUT_PATH` & `SUPPORT_BIP38` values in all cryptocurrencies. 
- Add: `NAME` value in all networks. 
- Add: `name_only` param for change, role, and ecc indexes on derivation

**Enhancements:**

- Change: getting `raw` of Point to `raw_encode`
- Modify: ECC implementation for `HDWDerivation`
- Modify: return language value & `from_entropy` funcs of all Mnemonics
- Refactor: renamed `ecc` to `eccs`
- Refactor: renamed `const` to `consts`

**Fix Bugs:**

- Fix: `version` of CardanoHD `root_xprivate_key` & `xprivate_key` functions
- Fix: Unknown arg name for all Seed `from_mnemonic` functions
- Fix: `from_index` function setup of `CustomDerivation`
- Fix: `public_key_type` of Electrum-V2 HD segwit-address

## [v3.4.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.4.0) (2025-03-15)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.3.0...v3.4.0)

**New Cryptocurrencies:**

| Name                                      | Symbol | Coin Type | Networks  |
|:------------------------------------------|:------:|:---------:|:---------:|
| [Neutron](https://github.com/neutron-org) |  NTRN  |    118    | `mainnet` |

**New Additions:**

- Add: `is_valid` function for validating entropies & seeds hex string
- Add: `is_valid_key` function for validating extended(x)-keys string

**Fix Bugs:**

- Fix: Phantom client base58 encode of Solana

## [v3.3.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.3.0) (2025-02-16)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.2.3...v3.3.0)

**New Cryptocurrencies:**

| Name                                    | Symbol | Coin Type | Networks  |
|:----------------------------------------|:------:|:---------:|:---------:|
| [dYdX](https://github.com/dydxprotocol) |  DYDX  | 22000118  | `mainnet` |

**Improvements:**

- Add: SLIP-0044 coin types on single file
- Update: All cryptocurrencies coin-type into SLIP44
- Modify: Both `eCash` & `e-Gulden` class names

**Fix Bugs:**

- Fix: Osmosis coin-type into `10000118` value

## [v3.2.3](https://github.com/hdwallet-io/python-hdwallet/tree/v3.2.3) (2025-01-14)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.2.1...v3.2.3)

**Improvements:**

- Update: The HDWDerivation `ecc` parameter now accepts an ECC instance
- Drop: List items are converted into a string in case of an exception

**Fix Bugs:**

- Fix: HDWDerivation `ecc` constant value on clean
- Fix: ECC parameter instant checker on HDWDerivation

## [v3.2.1](https://github.com/hdwallet-io/python-hdwallet/tree/v3.2.1) (2025-01-08)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.2.0...v3.2.1)

**Fix Bugs:**

- Fix: import SeedError exception on Cardano seed

## [v3.2.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.2.0) (2024-12-15)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.1.0...v3.2.0)

**Improvements:**

- Modify default address assignment to align with HD wallet standards and semantic configurations.
- Set default Electrum V1 and V2 HD's wif_prefix into `Bitcoin.NETWORKS.MAINNET.WIF_PREFIX`

**Fix Bugs:**

- Fix: WIF value return funcs of BIP32, Electrum-V1 & Electrum-V2 HD's
- Fix: Tezos address return function

**Closed issues:**

- Fix: use default HD class issue #107

## [v3.1.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.1.0) (2024-12-13)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.0.1...v3.1.0)

**New Additions:**

- Add `WIFError` class on exception
- Add more const values for `SLIP10_SECP256K1_CONST`
  - PRIVATE_KEY_UNCOMPRESSED_PREFIX=0x00, 
  - PRIVATE_KEY_COMPRESSED_PREFIX=0x01 
  - CHECKSUM_BYTE_LENGTH=4

**Enhancements:**

- Upgrade Wallet Import Format (WIF) implementations of all functions
- Update `from_wif`, `root_wif`, and `wif` of BIP32 HD functions
- Update `from_wif`, `master_wif`, and `wif` of Electrum-V1 HD functions
- Update `master_wif`, and `wif` of Electrum-V2 HD functions
- Update `master_wif`, `root_wif`, and `wif` of maine HDWallet functions
- Moved `get_checksum` function from wif.py into crypto.py

**Fix Bugs:**

- Fix Cardano testnet network extended versions

**Merge pull requests:**

- Fix bitcoin-cash regtest config #104 (@amikingo)

## [v3.0.1](https://github.com/hdwallet-io/python-hdwallet/tree/v3.0.1) (2024-11-27)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v3.0.0...v3.0.1)

**Improvements:**

- Include a Source link in our PyPI metadata, pointing directly to this repository. 

## [v3.0.0](https://github.com/hdwallet-io/python-hdwallet/tree/v3.0.0) (2024-11-26)

[Full Changelog](https://github.com/hdwallet-io/python-hdwallet/compare/v2.2.1...v3.0.0)

We are pleased to announce the release of **python-hdwallet v3.0.0**, a comprehensive update introducing new standards, enhanced functionality, and expanded support for diverse blockchain ecosystems.

**New Features:**

- Full support for entropy generation and mnemonic phrase creation for: `Algorand`, `Electrum-V1`, `Electrum-V2`, `Monero`
-  Add new Elliptic Curve Cryptography's (ECCs): `Kholaw-Ed25519`, `SLIP10-Ed25519`, `SLIP10-Ed25519-Blake2b`, `SLIP10-Ed25519-Monero`, `SLIP10-Nist256p1` algorithms.
- Add support for seed generation specific to: `Algorand`, `Cardano`,  `Electrum-V1`, `Electrum-V2`, `Monero`
- Extended support for Hierarchical Deterministic structures, including: `BIP86`, `Cardano`, `Electrum-V1`, `Electrum-V2`, `Monero`
- Support for advanced derivations: `BIP86`, `CIP1852`, `Electrum`, `Monero`, `HDW (Our own derivation method)` 
- Comprehensive support for generating addresses across a wide range of protocols and formats: `Algorand`, `Aptos`, `Avalanche`, `Cardano`, `Cosmos`, `EOS`, `Ergo`, `Ethereum`, `Filecoin`, `Harmony`, `Icon`, `Injective`, `Monero`, `MultiversX`, `Nano`, `Near`, `Neo`, `OKT-Chain`, `P2TR`, `Ripple`, `Solana`, `Stellar`, `Sui`, `Tezos`, `Tron`, `XinFin`, `Zilliqa`
- BIP38: Secure, password-protected private key handling

**New Cryptocurrencies:**

With the integration of multiple Elliptic Curve Cryptography (ECC) algorithms, we have significantly expanded our support, enabling enhanced compatibility and functionality for a wide range of cryptocurrencies.

<details>
  <summary>See more</summary><br/>


| Name             | Symbol | Coin Type |             Networks             |
|:-----------------|:------:|:---------:|:--------------------------------:|
| Adcoin           |  ACC   |    161    |            `mainnet`             |
| Akash-Network    |  AKT   |    118    |            `mainnet`             |
| Algorand         |  ALGO  |    283    |            `mainnet`             |
| Aptos            |  APT   |    637    |            `mainnet`             |
| Arbitrum         |  ARB   |    60     |            `mainnet`             |
| Avalanche        |  AVAX  |   9000    |            `mainnet`             |
| Avian            |  AVN   |    921    |            `mainnet`             |
| Axelar           |  AXL   |    118    |            `mainnet`             |
| Band-Protocol    |  BAND  |    494    |            `mainnet`             |
| Binance          |  BNB   |    714    |            `mainnet`             |
| Bitcoin-Atom     |  BCA   |    185    |            `mainnet`             |
| Bitcoin-Cash-SLP |  SLP   |    145    |       `mainnet`, `testnet`       |
| Bitcoin-Green    |  BITG  |    222    |            `mainnet`             |
| Bitcoin-Private  |  BTCP  |    183    |       `mainnet`, `testnet`       |
| Cardano          |  ADA   |   1815    |       `mainnet`, `testnet`       |
| Celo             |  CELO  |   52752   |            `mainnet`             |
| Chihuahua        |  HUA   |    118    |            `mainnet`             |
| Cosmos           |  ATOM  |    118    |            `mainnet`             |
| DeepOnion        | ONION  |    305    |            `mainnet`             |
| Divi             |  DIVI  |    301    |       `mainnet`, `testnet`       |
| eCash            |  XEC   |    145    |       `mainnet`, `testnet`       |
| E-coin           |  ECN   |    115    |            `mainnet`             |
| e-Gulden         |  EFL   |    78     |            `mainnet`             |
| EOS              |  EOS   |    194    |            `mainnet`             |
| Ergo             |  ERG   |    429    |       `mainnet`, `testnet`       |
| Evrmore          |  EVR   |    175    |       `mainnet`, `testnet`       |
| Fantom           |  FTM   |    60     |            `mainnet`             |
| Fetch.ai         |  FET   |    118    |            `mainnet`             |
| Filecoin         |  FIL   |    461    |            `mainnet`             |
| Firo             |  FIRO  |    136    |            `mainnet`             |
| Foxdcoin         |  FOXD  |    175    |       `mainnet`, `testnet`       |
| Harmony          |  ONE   |   1023    |            `mainnet`             |
| Horizen          |  ZEN   |    121    |            `mainnet`             |
| Huobi-Token      |   HT   |    553    |            `mainnet`             |
| Icon             |  ICX   |    74     |            `mainnet`             |
| Injective        |  INJ   |    60     |            `mainnet`             |
| InsaneCoin       |  INSN  |    68     |            `mainnet`             |
| IRISnet          |  IRIS  |    566    |            `mainnet`             |
| Kava             |  KAVA  |    459    |            `mainnet`             |
| Landcoin         |  LDCN  |    63     |            `mainnet`             |
| Metis            | METIS  |    60     |            `mainnet`             |
| Monero           |  XMR   |    128    | `mainnet`, `stagenet`, `testnet` |
| Monk             |  MONK  |    214    |            `mainnet`             |
| MultiversX       |  EGLD  |    508    |            `mainnet`             |
| Nano             |  XNO   |    165    |            `mainnet`             |
| Near             |  NEAR  |    397    |            `mainnet`             |
| Neo              |  NEO   |    888    |            `mainnet`             |
| Nine-Chronicles  |  NCG   |    567    |            `mainnet`             |
| OKT-Chain        |  OKT   |    996    |            `mainnet`             |
| Onix             |  ONX   |    174    |            `mainnet`             |
| Ontology         |  ONT   |   1024    |            `mainnet`             |
| Optimism         |   OP   |    60     |            `mainnet`             |
| Osmosis          |  OSMO  |    118    |            `mainnet`             |
| Particl          |  PART  |    44     |            `mainnet`             |
| Pi-Network       |   PI   |  314159   |            `mainnet`             |
| Polygon          | MATIC  |    60     |            `mainnet`             |
| PoSW-Coin        |  POSW  |    47     |            `mainnet`             |
| Ripple           |  XRP   |    144    |            `mainnet`             |
| Ritocoin         |  RITO  |   19169   |            `mainnet`             |
| Secret           |  SCRT  |    529    |            `mainnet`             |
| Shentu           |  CTK   |    118    |            `mainnet`             |
| Solana           |  SOL   |    501    |            `mainnet`             |
| Stafi            |  FIS   |    907    |            `mainnet`             |
| Stellar          |  XLM   |    148    |            `mainnet`             |
| Sui              |  SUI   |    784    |            `mainnet`             |
| Terra            |  LUNA  |    330    |            `mainnet`             |
| Tezos            |  XTZ   |   1729    |            `mainnet`             |
| Theta            | THETA  |    500    |            `mainnet`             |
| TWINS            | TWINS  |    970    |       `mainnet`, `testnet`       |
| VeChain          |  VET   |    818    |            `mainnet`             |
| Verge            |  XVG   |    77     |            `mainnet`             |
| Voxels           |  VOX   |    129    |            `mainnet`             |
| Wagerr           |  WGR   |     0     |            `mainnet`             |
| Zetacoin         |  ZET   |    719    |            `mainnet`             |
| Zilliqa          |  ZIL   |    313    |            `mainnet`             |
| ZooBC            |  ZBC   |    883    |            `mainnet`             |

</details>

**Enhancements:**

- Derivation Path Ranges For Dumps: The derivation path supports ranges defined directly in the string format. For example:
    - A path like `m/0-2` will be automatically unrolled into:
      ```
      m/0
      m/1
      m/2
      ```
  - Tuple-Based Ranges: Tuples can be passed directly to the derivation function for dynamic and programmatic control. For instance:
    ```python
    BIP44Derivation(address=(0, 2))
    ```
    This will generate the derivation paths for accounts `m/44'/0'/0'/0/0` through `m/44'/0'/0'/0/2` inclusively.
      ```
      m/44'/0'/0'/0/0
      m/44'/0'/0'/0/1
      m/44'/0'/0'/0/2
      ```
- Modify BIP32 name into Custom derivation.

**Closed issues:**

- Support Uncompressed addresses for SLIP10-Secp256k1 ECC #58 #50 
- Add BIP86 Hierarchical Deterministic and P2RT Address for Bitcoin and Qtum #27 #84 
- Add BIP84 Hierarchical Deterministic for Litecoin #78
- Add new cryptocurrencies #45 #76  #83

This release marks a significant milestone in delivering a robust, versatile tool for developers and blockchain enthusiasts. For more https://hdwallet.readthedocs.io
