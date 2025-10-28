=================================
Hierarchical Deterministic Wallet
=================================

|Build Status| |PyPI Version| |Documentation Status| |PyPI License| |PyPI Python Version| |Coverage Status|

.. |Build Status| image:: https://img.shields.io/github/actions/workflow/status/hdwallet-io/python-hdwallet/build.yml
   :target: https://github.com/hdwallet-io/python-hdwallet/actions/workflows/build.yml

.. |PyPI Version| image:: https://img.shields.io/pypi/v/hdwallet.svg?color=blue
   :target: https://pypi.org/project/hdwallet

.. |Documentation Status| image:: https://readthedocs.org/projects/hdwallet/badge/?version=master
   :target: https://hdwallet.readthedocs.io/projects/python

.. |PyPI License| image:: https://img.shields.io/pypi/l/hdwallet?color=black
   :target: https://pypi.org/project/hdwallet

.. |PyPI Python Version| image:: https://img.shields.io/pypi/pyversions/hdwallet.svg
   :target: https://pypi.org/project/hdwallet

.. |Coverage Status| image:: https://coveralls.io/repos/github/hdwallet-io/python-hdwallet/badge.svg?branch=master
   :target: https://coveralls.io/github/hdwallet-io/python-hdwallet?branch=master

Python-based library implementing a Hierarchical Deterministic (HD) Wallet generator for 200+ cryptocurrencies.

.. epigraph::

    This library offers a flexible and scalable solution for developers integrating multi-currency wallet functionality. It adheres to standard protocols for compatibility with other wallets and services, and provides features like secure seed generation, robust key management, and streamlined account control. By simplifying blockchain interactions, it enhances the developer experience and strengthens end-user security.

    For TypeScript/JavaScript support, explore `hdwallet.js <https://github.com/hdwallet-io/hdwallet.js>`_, the official port of this library. Try it live at https://hdwallet.online, our interactive web playground.

.. list-table::
   :widths: 30 200
   :header-rows: 1

   * - Features
     - Protocols
   * - Cryptocurrencies
     - `#supported-cryptocurrencies <https://hdwallet.io/cryptocurrencies>`_
   * - Entropies
     - ``Algorand``, ``BIP39``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``
   * - Mnemonics
     - ``Algorand``, ``BIP39``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``
   * - Seeds
     - ``Algorand``, ``BIP39``, ``Cardano``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``
   * - Elliptic Curve Cryptography's
     - ``Kholaw-Ed25519``, ``SLIP10-Ed25519``, ``SLIP10-Ed25519-Blake2b``, ``SLIP10-Ed25519-Monero``, ``SLIP10-Nist256p1``, ``SLIP10-Secp256k1``
   * - Hierarchical Deterministic's
     - ``Algorand``, ``BIP32``, ``BIP44``, ``BIP49``, ``BIP84``, ``BIP86``, ``BIP141``, ``Cardano``, ``Electrum-V1``, ``Electrum-V2``, ``Monero``
   * - Derivations
     - ``BIP44``, ``BIP49``, ``BIP84``, ``BIP86``, ``CIP1852``, ``Custom``, ``Electrum``, ``Monero``, ``HDW (Our own custom derivation)``
   * - Addresses
     - ``Algorand``, ``Aptos``, ``Avalanche``, ``Cardano``, ``Cosmos``, ``EOS``, ``Ergo``, ``Ethereum``, ``Filecoin``, ``Harmony``, ``Icon``, ``Injective``, ``Monero``, ``MultiversX``, ``Nano``, ``Near``, ``Neo``, ``OKT-Chain``, ``P2PKH``, ``P2SH``, ``P2TR``, ``P2WPKH``, ``P2WPKH-In-P2SH``, ``P2WSH``, ``P2WSH-In-P2SH``, ``Ripple``, ``Solana``, ``Stellar``, ``Sui``, ``Tezos``, ``Tron``, ``XinFin``, ``Zilliqa``
   * - Others
     - ``BIP38``, ``Wallet Import Format``, ``Serialization``
