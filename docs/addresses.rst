:orphan:

=========
Addresses
=========

.. autoclass:: hdwallet.addresses.ADDRESSES
    :members:

>>> from hdwallet.addresses import ADDRESSES
>>> ADDRESSES.names()
['Algorand', 'Aptos', 'Avalanche', 'Cardano', 'Cosmos', 'EOS', 'Ergo', 'Ethereum', 'Filecoin', 'Harmony', 'Icon', 'Injective', 'Monero', 'MultiversX', 'Nano', 'Near', 'Neo', 'OKT-Chain', 'P2PKH', 'P2SH', 'P2TR', 'P2WPKH', 'P2WPKH-In-P2SH', 'P2WSH', 'P2WSH-In-P2SH', 'Ripple', 'Solana', 'Stellar', 'Sui', 'Tezos', 'Ton', 'Tron', 'XinFin', 'Zilliqa']
>>> ADDRESSES.classes()
[<class 'hdwallet.addresses.algorand.AlgorandAddress'>, <class 'hdwallet.addresses.aptos.AptosAddress'>, <class 'hdwallet.addresses.avalanche.AvalancheAddress'>, <class 'hdwallet.addresses.cardano.CardanoAddress'>, <class 'hdwallet.addresses.cosmos.CosmosAddress'>, <class 'hdwallet.addresses.eos.EOSAddress'>, <class 'hdwallet.addresses.ergo.ErgoAddress'>, <class 'hdwallet.addresses.ethereum.EthereumAddress'>, <class 'hdwallet.addresses.filecoin.FilecoinAddress'>, <class 'hdwallet.addresses.harmony.HarmonyAddress'>, <class 'hdwallet.addresses.icon.IconAddress'>, <class 'hdwallet.addresses.injective.InjectiveAddress'>, <class 'hdwallet.addresses.monero.MoneroAddress'>, <class 'hdwallet.addresses.multiversx.MultiversXAddress'>, <class 'hdwallet.addresses.nano.NanoAddress'>, <class 'hdwallet.addresses.near.NearAddress'>, <class 'hdwallet.addresses.neo.NeoAddress'>, <class 'hdwallet.addresses.okt_chain.OKTChainAddress'>, <class 'hdwallet.addresses.p2pkh.P2PKHAddress'>, <class 'hdwallet.addresses.p2sh.P2SHAddress'>, <class 'hdwallet.addresses.p2tr.P2TRAddress'>, <class 'hdwallet.addresses.p2wpkh.P2WPKHAddress'>, <class 'hdwallet.addresses.p2wpkh_in_p2sh.P2WPKHInP2SHAddress'>, <class 'hdwallet.addresses.p2wsh.P2WSHAddress'>, <class 'hdwallet.addresses.p2wsh_in_p2sh.P2WSHInP2SHAddress'>, <class 'hdwallet.addresses.ripple.RippleAddress'>, <class 'hdwallet.addresses.solana.SolanaAddress'>, <class 'hdwallet.addresses.stellar.StellarAddress'>, <class 'hdwallet.addresses.sui.SuiAddress'>, <class 'hdwallet.addresses.tezos.TezosAddress'>, <class 'hdwallet.addresses.tron.TronAddress'>, <class 'hdwallet.addresses.xinfin.XinFinAddress'>, <class 'hdwallet.addresses.zilliqa.ZilliqaAddress'>]
>>> from hdwallet.addresses.p2wsh import P2WSHAddress
>>> ADDRESSES.address(name="P2WSH")
<class 'hdwallet.addresses.p2wsh.P2WSHAddress'>
>>> ADDRESSES.address(name="P2WSH") == P2WSHAddress
True
>>> ADDRESSES.is_address(name="P2WSH")
True

.. autoclass:: hdwallet.addresses.iaddress.IAddress
    :members:

.. autoclass:: hdwallet.addresses.algorand.AlgorandAddress
    :members:

>>> from hdwallet.addresses.algorand import AlgorandAddress
>>> AlgorandAddress.name()
'Algorand'
>>> address: str = AlgorandAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'2FDJMWB65EKEQ6DDLNKX2UK2KAVQINTIDDP6O5SXG52GWT2XS6GWBBFHDM'
>>> AlgorandAddress.decode(address=address)
'd14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d'

.. autoclass:: hdwallet.addresses.aptos.AptosAddress
    :members:

>>> from hdwallet.addresses.aptos import AptosAddress
>>> AptosAddress.name()
'Aptos'
>>> address: str = AptosAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'0x7d39ce271d420c8ae8fe93c07a2fbbfa733eec1c6d1fa4899058cbd48c433d'
>>> AptosAddress.decode(address=address)
'007d39ce271d420c8ae8fe93c07a2fbbfa733eec1c6d1fa4899058cbd48c433d'

.. autoclass:: hdwallet.addresses.avalanche.AvalancheAddress
    :members:

>>> from hdwallet.addresses.avalanche import AvalancheAddress
>>> AvalancheAddress.name()
'Avalanche'
>>> address: str = AvalancheAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'P-avax16zfzju9q6y9nfqeaxp3yvfvzvrx9rlamqm0t2x'
>>> AvalancheAddress.decode(address=address)
'd0922970a0d10b34833d306246258260cc51ffbb'

.. autoclass:: hdwallet.addresses.cardano.CardanoAddress
    :members:

>>> from hdwallet.addresses.cardano import CardanoAddress
>>> CardanoAddress.name()
'Cardano'
>>> address: str = CardanoAddress.encode(
...     public_key="00e55487c92c1913439f336b1b2dc316da6e88c02a157208f98781494b87f27eb8",
...     chain_code="d537f39c41f0f781f543c4c512cac38927e5ebd3cd82b870dd7ce94de9e510b4",
...     encode_type="byron-icarus"
... )
>>> address
'Ae2tdPwUPEZJy1etGnbAt9L92eC2goQEVzsQKpeg9vGYyy6wRSHRNLnTXhL'
>>> CardanoAddress.decode(address=address, decode_type="byron-icarus")
'de155535f68a45e86483a4d1381c17717a9d09b644720b4beae8145d'
>>>
>>> address: str = CardanoAddress.encode_byron_icarus(
...     public_key="00e55487c92c1913439f336b1b2dc316da6e88c02a157208f98781494b87f27eb8",
...     chain_code="d537f39c41f0f781f543c4c512cac38927e5ebd3cd82b870dd7ce94de9e510b4",
... )
>>> address
'Ae2tdPwUPEZJy1etGnbAt9L92eC2goQEVzsQKpeg9vGYyy6wRSHRNLnTXhL'
>>> CardanoAddress.decode_byron_icarus(address=address)
'de155535f68a45e86483a4d1381c17717a9d09b644720b4beae8145d'
>>>
>>> address: str = CardanoAddress.encode_byron_legacy(
...     public_key="00e55487c92c1913439f336b1b2dc316da6e88c02a157208f98781494b87f27eb8",
...     path="m/0'/0234'/123/243/5/7",
...     path_key="39ddaa1e5719d88d6b53eda320f3dbe8c012d24abe33f4ac358fe78df43d5814",
...     chain_code="d537f39c41f0f781f543c4c512cac38927e5ebd3cd82b870dd7ce94de9e510b4"
... )
>>> address
'Un4ZpTvXtoKmqsCFyDCG86z27yfgkyQ3ZidQSPQqf9YNk4DSCFqVfutBFTQCgMM9K2txjuBMBFs8ThUaB2zarMiPVaEby7hSg97nYfJjAJXx4cmP'
>>> CardanoAddress.decode_byron_legacy(address=address)
'5c27044e9fe6cd3f89df7d725dccc5f015ad1a3e7e5bb39f32a595e7d9758587b1078dfb12d017b4860de1a05dcecc07eea0291e18937278d865edab3840'
>>>
>>> address: str = CardanoAddress.encode_shelley(
...     public_key="00e55487c92c1913439f336b1b2dc316da6e88c02a157208f98781494b87f27eb8",
...     staking_public_key="007505bd415a4d5b21cb5be55360adeff02192ad952b5a1728e65010aea306aa54"
... )
>>> address
'addr1qy56fgzsfwpftatef0sxma2sksyxm7wf9husxazh0ph7n30zmrqdt7aqd5mfa0fs69dzs30svnqrc6v3s62l2nmg0c7q0d0m7j'
>>> CardanoAddress.decode_shelley(address=address)
'29a4a0504b8295f5794be06df550b4086df9c92df9037457786fe9c5e2d8c0d5fba06d369ebd30d15a2845f064c03c69918695f54f687e3c'
>>>
>>> address: str = CardanoAddress.encode_shelley_staking(
...     public_key="00e55487c92c1913439f336b1b2dc316da6e88c02a157208f98781494b87f27eb8"
... )
>>> address
'stake1uy56fgzsfwpftatef0sxma2sksyxm7wf9husxazh0ph7n3g5jc0qy'
>>> CardanoAddress.decode_shelley_staking(address=address)
'29a4a0504b8295f5794be06df550b4086df9c92df9037457786fe9c5'

.. autoclass:: hdwallet.addresses.cosmos.CosmosAddress
    :members:

>>> from hdwallet.addresses.cosmos import CosmosAddress
>>> CosmosAddress.name()
'Cosmos'
>>> address: str = CosmosAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'cosmos16zfzju9q6y9nfqeaxp3yvfvzvrx9rlam4ezznm'
>>> CosmosAddress.decode(address=address)
'd0922970a0d10b34833d306246258260cc51ffbb'

.. autoclass:: hdwallet.addresses.eos.EOSAddress
    :members:

>>> from hdwallet.addresses.eos import EOSAddress
>>> EOSAddress.name()
'EOS'
>>> address: str = EOSAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'EOS7ibykhJSC7L399MVKebcJVeeTotrvaqxTZD18M1igKJpEEwVD3'
>>> EOSAddress.decode(address=address)
'0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429'

.. autoclass:: hdwallet.addresses.ergo.ErgoAddress
    :members:

>>> from hdwallet.addresses.ergo import ErgoAddress
>>> ErgoAddress.name()
'Ergo'
>>> address: str = ErgoAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429", network_type="mainnet")
>>> address
'9hMB97bUb7FJZ9uuZiYPnPyu5fTjHCK1Q5gmTUSWCS2b9PTymeg'
>>> ErgoAddress.decode(address=address, network_type="mainnet")
'0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429'

.. autoclass:: hdwallet.addresses.ethereum.EthereumAddress
    :members:

>>> from hdwallet.addresses.ethereum import EthereumAddress
>>> EthereumAddress.name()
'Ethereum'
>>> address: str = EthereumAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'0xe349A2f7dF70161e529E4C2982828A50c20FfDaB'
>>> EthereumAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.filecoin.FilecoinAddress
    :members:

>>> from hdwallet.addresses.filecoin import FilecoinAddress
>>> FilecoinAddress.name()
'Filecoin'
>>> address: str = FilecoinAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'f1ziusa3hzevazyixnvy6falwmykiuozkb22utdea'
>>> FilecoinAddress.decode(address=address, address_type="secp256k1")
'ca29206cf925419c22edae3c502eccc291476541'

.. autoclass:: hdwallet.addresses.harmony.HarmonyAddress
    :members:

>>> from hdwallet.addresses.harmony import HarmonyAddress
>>> HarmonyAddress.name()
'Harmony'
>>> address: str = HarmonyAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'one1udy69a7lwqtpu557fs5c9q522rpqlldt0rxe4v'
>>> HarmonyAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.icon.IconAddress
    :members:

>>> from hdwallet.addresses.icon import IconAddress
>>> IconAddress.name()
'Icon'
>>> address: str = IconAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'hx9756520d3d5f07cc3e1c9f75e279d51d330bfdce'
>>> IconAddress.decode(address=address)
'9756520d3d5f07cc3e1c9f75e279d51d330bfdce'

.. autoclass:: hdwallet.addresses.injective.InjectiveAddress
    :members:

>>> from hdwallet.addresses.injective import InjectiveAddress
>>> InjectiveAddress.name()
'Injective'
>>> address: str = InjectiveAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'inj1udy69a7lwqtpu557fs5c9q522rpqlldt2tluvt'
>>> InjectiveAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.monero.MoneroAddress
    :members:

>>> from hdwallet.addresses.monero import MoneroAddress
>>> MoneroAddress.name()
'Monero'
>>> address: str = MoneroAddress.encode(
...     spend_public_key="628247d3de93857cdd360fee4aef9a67ecfebedfe8eaec9cf6be35eacc895ca7",
...     view_public_key="1bc7b28fdaec0ec300c8c2759b1bf01f5300bb8465f736c55d64c5d87ec5e311"
... )
>>> address
'45MdDdMknD2MtLcqtCBAfTJPDBhBiQ2QjTFkG6kbAYyhUxAPk2iygXPZcmtgou9dBV6EtHgRFYkMja1gncWwRdUv2vsuWU7'
>>> MoneroAddress.decode(address=address)
('628247d3de93857cdd360fee4aef9a67ecfebedfe8eaec9cf6be35eacc895ca7', '1bc7b28fdaec0ec300c8c2759b1bf01f5300bb8465f736c55d64c5d87ec5e311')

.. autoclass:: hdwallet.addresses.multiversx.MultiversXAddress
    :members:

>>> from hdwallet.addresses.multiversx import MultiversXAddress
>>> MultiversXAddress.name()
'MultiversX'
>>> address: str = MultiversXAddress.encode(
...     public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d"
... )
>>> address
'erd169rfvkp7ay2ys7rrtd2h65262q4sgdngrr07wajhxa6xkn6hj7xsdet995'
>>> MultiversXAddress.decode(address=address)
'd14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d'

.. autoclass:: hdwallet.addresses.nano.NanoAddress
    :members:

>>> from hdwallet.addresses.nano import NanoAddress
>>> NanoAddress.name()
'Nano'
>>> address: str = NanoAddress.encode(public_key="006aea61eeed872052377ab16b0fc5d9b9f142be59ac1488e6610645dedb4da45c")
>>> address
'nano_1tqce9qgu3s1cauqoedd3z4xmghjacz7md1nj5m843k7uufnub4wem9ziqhs'
>>> NanoAddress.decode(address=address)
'6aea61eeed872052377ab16b0fc5d9b9f142be59ac1488e6610645dedb4da45c'

.. autoclass:: hdwallet.addresses.near.NearAddress
    :members:

>>> from hdwallet.addresses.nano import NanoAddress
>>> NanoAddress.name()
'Nano'
>>> address: str = NanoAddress.encode(public_key="006aea61eeed872052377ab16b0fc5d9b9f142be59ac1488e6610645dedb4da45c")
>>> address
'nano_1tqce9qgu3s1cauqoedd3z4xmghjacz7md1nj5m843k7uufnub4wem9ziqhs'
>>> NanoAddress.decode(address=address)
'6aea61eeed872052377ab16b0fc5d9b9f142be59ac1488e6610645dedb4da45c'

.. autoclass:: hdwallet.addresses.neo.NeoAddress
    :members:

>>> from hdwallet.addresses.neo import NeoAddress
>>> NeoAddress.name()
'Neo'
>>> address: str = NeoAddress.encode(public_key="02e4bd97a82a8f3e575a9a35b7cca19cd730addd499a2bd4e9a9811df8bfc35e51")
>>> address
'AKMzgMj2nGYoy7fuDcQySog3STQ9uZfxFU'
>>> NeoAddress.decode(address=address)
'275c63df3b7d5362485e157872a22202101a5f6a'

.. autoclass:: hdwallet.addresses.okt_chain.OKTChainAddress
    :members:

>>> from hdwallet.addresses.okt_chain import OKTChainAddress
>>> OKTChainAddress.name()
'OKT-Chain'
>>> address: str = OKTChainAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'ex1udy69a7lwqtpu557fs5c9q522rpqlldtgt7ahy'
>>> OKTChainAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.p2pkh.P2PKHAddress
    :members:

>>> from hdwallet.addresses.p2pkh import P2PKHAddress
>>> P2PKHAddress.name()
'P2PKH'
>>> address: str = P2PKHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'1L1peQYCrrMPRPbbT9UCXainKtczSiekmy'
>>> P2PKHAddress.decode(address=address)
'd0922970a0d10b34833d306246258260cc51ffbb'

.. autoclass:: hdwallet.addresses.p2sh.P2SHAddress
    :members:

>>> from hdwallet.addresses.p2sh import P2SHAddress
>>> P2SHAddress.name()
'P2SH'
>>> address: str = P2SHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'3DpehQMAa7jQHoVRnzoKz2w6Pr68Lctxgr'
>>> P2SHAddress.decode(address=address)
'85131e393e442cda8939042ef5709c8a18ddbae6'

.. autoclass:: hdwallet.addresses.p2tr.P2TRAddress
    :members:

>>> from hdwallet.addresses.p2tr import P2TRAddress
>>> P2TRAddress.name()
'P2TR'
>>> address: str = P2TRAddress.encode(
...     public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429"
... )
>>> address
'bc1pa73duht4ulz02gdn97t6eu0rcunsnmtqylxxr4ds22hxu8clcj4qt8e9h5'
>>> P2TRAddress.decode(address=address)
'efa2de5d75e7c4f521b32f97acf1e3c72709ed6027cc61d5b052ae6e1f1fc4aa'

.. autoclass:: hdwallet.addresses.p2wpkh.P2WPKHAddress
    :members:

>>> from hdwallet.addresses.p2wpkh import P2WPKHAddress
>>> P2WPKHAddress.name()
'P2WPKH'
>>> address: str = P2WPKHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'bc1q6zfzju9q6y9nfqeaxp3yvfvzvrx9rlamrrufhk'
>>> P2WPKHAddress.decode(address=address)
'd0922970a0d10b34833d306246258260cc51ffbb'

.. autoclass:: hdwallet.addresses.p2wpkh_in_p2sh.P2WPKHInP2SHAddress
    :members:

>>> from hdwallet.addresses.p2wpkh_in_p2sh import P2WPKHInP2SHAddress
>>> P2WPKHInP2SHAddress.name()
'P2WPKH-In-P2SH'
>>> address: str = P2WPKHInP2SHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'39EKCqjpGxLxudcbgNBQDq6CcKg6kQG1hT'
>>> P2WPKHInP2SHAddress.decode(address=address)
'52b433640add2e12b63432fd84e8817ef9369ad0'

.. autoclass:: hdwallet.addresses.p2wsh.P2WSHAddress
    :members:

>>> from hdwallet.addresses.p2wsh import P2WSHAddress
>>> P2WSHAddress.name()
'P2WSH'
>>> address: str = P2WSHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'bc1qfv2azdx3776jxve27xpq52w97k0ke47969jt2pnm8yg4cnxnxdxqdfvmyp'
>>> P2WSHAddress.decode(address=address)
'4b15d134d1f7b523332af1820a29c5f59f6cd7c5d164b5067b39115c4cd3334c'

.. autoclass:: hdwallet.addresses.p2wsh_in_p2sh.P2WSHInP2SHAddress
    :members:

>>> from hdwallet.addresses.p2wsh_in_p2sh import P2WSHInP2SHAddress
>>> P2WSHInP2SHAddress.name()
'P2WSH-In-P2SH'
>>> address: str = P2WSHInP2SHAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'3DsBoAQ5ZbzuZrXRmJmErWiyp4eLi1DrAs'
>>> P2WSHInP2SHAddress.decode(address=address)
'858de90e467c7297565d9d86e9ea77e14f9b6ece'

.. autoclass:: hdwallet.addresses.ripple.RippleAddress
    :members:

>>> from hdwallet.addresses.ripple import RippleAddress
>>> RippleAddress.name()
'Ripple'
>>> address: str = RippleAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'rLrFeQYUiiMPRPbbT97UX258KtczS5ekmy'
>>> RippleAddress.decode(address=address)
'd0922970a0d10b34833d306246258260cc51ffbb'

.. autoclass:: hdwallet.addresses.solana.SolanaAddress
    :members:

>>> from hdwallet.addresses.solana import SolanaAddress
>>> SolanaAddress.name()
'Solana'
>>> address: str = SolanaAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'F5vdvUASQmeL76F62X4ff7uR3EQegeCibH7M72pY2qK2'
>>> SolanaAddress.decode(address=address)
'd14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d'

.. autoclass:: hdwallet.addresses.stellar.StellarAddress
    :members:

>>> from hdwallet.addresses.stellar import StellarAddress
>>> StellarAddress.name()
'Stellar'
>>> address: str = StellarAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'SDIUNFSYH3URISDYMNNVK7KRLJICWBBWNAMN7Z3WK43XI22PK6LY2GKP'
>>> StellarAddress.decode(address=address)
'd14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d'

.. autoclass:: hdwallet.addresses.sui.SuiAddress
    :members:

>>> from hdwallet.addresses.sui import SuiAddress
>>> SuiAddress.name()
'Sui'
>>> address: str = SuiAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'0xdff86ae2063acd23c139b94598d8b4b7347bd9794c301bbaeeea12fe6b330178'
>>> SuiAddress.decode(address=address)
'dff86ae2063acd23c139b94598d8b4b7347bd9794c301bbaeeea12fe6b330178'

.. autoclass:: hdwallet.addresses.tezos.TezosAddress
    :members:

>>> from hdwallet.addresses.tezos import TezosAddress
>>> TezosAddress.name()
'Tezos'
>>> address: str = TezosAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'tz1PBvuXpgELdV3JuNYwbd5DXHWvrj9gS5JJ'
>>> TezosAddress.decode(address=address)
'26f0dbb538759db4e8256a6f11ba88ec9c214f11'

.. autoclass:: hdwallet.addresses.ton.TonAddress
    :members:

>>> from hdwallet.addresses.ton import TonAddress
>>> TonAddress.name()
'Ton'
>>> address: str = TonAddress.encode(public_key="00d14696583ee9144878635b557d515a502b04366818dfe7765737746b4f57978d")
>>> address
'UQAdGH9zh3uTnsckECChKLGOEmHbOqBJM6P3d2GPHhAtuzS2'
>>> TonAddress.decode(address=address)
'1d187f73877b939ec7241020a128b18e1261db3aa04933a3f777618f1e102dbb'

.. autoclass:: hdwallet.addresses.tron.TronAddress
    :members:

>>> from hdwallet.addresses.tron import TronAddress
>>> TronAddress.name()
'Tron'
>>> address: str = TronAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'TWgzbxurHnC2TFQF5FfE3KPexrDKSK4nej'
>>> TronAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.xinfin.XinFinAddress
    :members:

>>> from hdwallet.addresses.xinfin import XinFinAddress
>>> XinFinAddress.name()
'XinFin'
>>> address: str = XinFinAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'xdce349A2f7dF70161e529E4C2982828A50c20FfDaB'
>>> XinFinAddress.decode(address=address)
'e349a2f7df70161e529e4c2982828a50c20ffdab'

.. autoclass:: hdwallet.addresses.zilliqa.ZilliqaAddress
    :members:

>>> from hdwallet.addresses.zilliqa import ZilliqaAddress
>>> ZilliqaAddress.name()
'Zilliqa'
>>> address: str = ZilliqaAddress.encode(public_key="0374a436044b4904bbd7a074b098d65fad39fc5b66f28da8440f10dbcf86568429")
>>> address
'zil1ahp99dssuhwz8mccwetm5m4gkh528wzw9lwdcf'
>>> ZilliqaAddress.decode(address=address)
'edc252b610e5dc23ef187657ba6ea8b5e8a3b84e'
