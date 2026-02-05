#!/usr/bin/env python3

from hdwallet.eccs import (
    IPrivateKey, IPublicKey, SLIP10Secp256k1PrivateKey
)
from hdwallet.consts import PUBLIC_KEY_TYPES
from hdwallet.utils import (
    bytes_to_string, get_bytes
)
from hdwallet.cryptocurrencies import (
    Bitcoin, BitcoinCash, Cosmos, Filecoin, Avalanche, Ergo, OKTChain, Harmony, Zilliqa, Injective
)
from hdwallet.addresses import (
    P2PKHAddress,
    P2SHAddress,
    P2TRAddress,
    P2WPKHAddress,
    P2WPKHInP2SHAddress,
    P2WSHAddress,
    P2WSHInP2SHAddress,
    BitcoinCashAddress,
    EthereumAddress,
    CosmosAddress,
    XinFinAddress,
    TronAddress,
    RippleAddress,
    FilecoinAddress,
    AvalancheAddress,
    EOSAddress,
    ErgoAddress,
    IconAddress,
    OKTChainAddress,
    HarmonyAddress,
    ZilliqaAddress,
    InjectiveAddress
)

private_key: IPrivateKey = SLIP10Secp256k1PrivateKey.from_bytes(get_bytes(
    "0000000000000000000000000000000000000000000000000000000000000001"
))
public_key: IPublicKey = private_key.public_key()

print("Private Key:", bytes_to_string(private_key.raw()))
print("Uncompressed Public Key:", bytes_to_string(public_key.raw_uncompressed()))
print("Compressed Public Key:", bytes_to_string(public_key.raw_compressed()), "\n")

p2pkh_address: str = P2PKHAddress.encode(
    public_key=public_key,
    public_key_address_prefix=Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX,
    public_key_type=PUBLIC_KEY_TYPES.UNCOMPRESSED
)
p2pkh_address_hash: str = P2PKHAddress.decode(
    address=p2pkh_address, public_key_address_prefix=Bitcoin.NETWORKS.MAINNET.PUBLIC_KEY_ADDRESS_PREFIX
)
print("P2PKH Address:", p2pkh_address, p2pkh_address_hash)

p2sh_address: str = P2SHAddress.encode(
    public_key=public_key,
    script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
)
p2sh_address_hash: str = P2SHAddress.decode(
    address=p2sh_address, script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
)
print("P2SH Address:", p2sh_address, p2sh_address_hash)

p2tr_address: str = P2TRAddress.encode(
    public_key=public_key,
    hrp=Bitcoin.NETWORKS.MAINNET.HRP,
    witness_version=Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2TR
)
p2tr_address_hash: str = P2TRAddress.decode(
    address=p2tr_address, hrp=Bitcoin.NETWORKS.MAINNET.HRP
)
print("P2TR Address:", p2tr_address, p2tr_address_hash)

p2wpkh_address: str = P2WPKHAddress.encode(
    public_key=public_key,
    hrp=Bitcoin.NETWORKS.MAINNET.HRP,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    witness_version=Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WPKH
)
p2wpkh_address_hash: str = P2WPKHAddress.decode(
    address=p2wpkh_address, hrp=Bitcoin.NETWORKS.MAINNET.HRP
)
print("P2WPKH Address:", p2wpkh_address, p2wpkh_address_hash)

p2wpkh_in_p2sh_address: str = P2WPKHInP2SHAddress.encode(
    public_key=public_key,
    script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
)
p2wpkh_in_p2sh_address_hash: str = P2WPKHInP2SHAddress.decode(
    address=p2wpkh_in_p2sh_address, script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX
)
print("P2WPKH-In-P2SH Address:", p2wpkh_in_p2sh_address, p2wpkh_in_p2sh_address_hash)

p2wsh_address: str = P2WSHAddress.encode(
    public_key=public_key,
    hrp=Bitcoin.NETWORKS.MAINNET.HRP,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED,
    witness_version=Bitcoin.NETWORKS.MAINNET.WITNESS_VERSIONS.P2WSH
)
p2wsh_address_hash: str = P2WSHAddress.decode(
    address=p2wsh_address, hrp=Bitcoin.NETWORKS.MAINNET.HRP
)
print("P2WSH Address:", p2wsh_address, p2wsh_address_hash)

p2wsh_in_p2sh_address: str = P2WSHInP2SHAddress.encode(
    public_key=public_key,
    script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
)
p2wsh_in_p2sh_address_hash: str = P2WSHInP2SHAddress.decode(
    address=p2wsh_in_p2sh_address,
    script_address_prefix=Bitcoin.NETWORKS.MAINNET.SCRIPT_ADDRESS_PREFIX,
)
print("P2WSH-In-P2SH Address:", p2wsh_in_p2sh_address, p2wsh_in_p2sh_address_hash)

bitcoincash_address: str = BitcoinCashAddress.encode(
    public_key=public_key,
    public_key_type=PUBLIC_KEY_TYPES.COMPRESSED
)
bitcoincash_address_hash: str = BitcoinCashAddress.decode(
    address=bitcoincash_address
)
print("BitcoinCash Address:", bitcoincash_address, bitcoincash_address_hash)

ethereum_address: str = EthereumAddress.encode(
    public_key=public_key, skip_checksum_encode=False
)
ethereum_address_hash: str = EthereumAddress.decode(
    address=ethereum_address, skip_checksum_encode=False
)
print("Ethereum Address:", ethereum_address, ethereum_address_hash)

cosmos_address: str = CosmosAddress.encode(
    public_key=public_key, hrp=Cosmos.NETWORKS.MAINNET.HRP
)
cosmos_address_hash: str = CosmosAddress.decode(
    address=cosmos_address, hrp=Cosmos.NETWORKS.MAINNET.HRP
)
print("Cosmos Address:", cosmos_address, cosmos_address_hash)

xinfin_address: str = XinFinAddress.encode(
    public_key=public_key, skip_checksum_encode=False
)
xinfin_address_hash: str = XinFinAddress.decode(
    address=xinfin_address, skip_checksum_encode=False
)
print("XinFin Address:", xinfin_address, xinfin_address_hash)

tron_address: str = TronAddress.encode(public_key=public_key)
tron_address_hash: str = TronAddress.decode(address=tron_address)
print("Tron Address:", tron_address, tron_address_hash)

ripple_address: str = RippleAddress.encode(public_key=public_key)
ripple_address_hash: str = RippleAddress.decode(address=ripple_address)
print("Ripple Address:", ripple_address, ripple_address_hash)

secp256k1_filecoin_address: str = FilecoinAddress.encode(
    public_key=public_key, address_type=Filecoin.ADDRESS_TYPES.SECP256K1
)
secp256k1_filecoin_address_hash: str = FilecoinAddress.decode(
    address=secp256k1_filecoin_address, address_type=Filecoin.ADDRESS_TYPES.SECP256K1
)
print("(Secp256k1) Filecoin Address:", secp256k1_filecoin_address, secp256k1_filecoin_address_hash)

bls_filecoin_address: str = FilecoinAddress.encode(
    public_key=public_key, address_type=Filecoin.ADDRESS_TYPES.BLS
)
bls_filecoin_address_hash: str = FilecoinAddress.decode(
    address=bls_filecoin_address, address_type=Filecoin.ADDRESS_TYPES.BLS
)
print("(BLS) Filecoin Address:", bls_filecoin_address, bls_filecoin_address_hash)

p_avalanche_address: str = AvalancheAddress.encode(
    public_key=public_key, address_type=Avalanche.ADDRESS_TYPES.P_CHAIN
)
p_avalanche_address_hash: str = AvalancheAddress.decode(
    address=p_avalanche_address, address_type=Avalanche.ADDRESS_TYPES.P_CHAIN
)
print("(P-Chain) Avalanche Address:", p_avalanche_address, p_avalanche_address_hash)

x_avalanche_address: str = AvalancheAddress.encode(
    public_key=public_key, address_type=Avalanche.ADDRESS_TYPES.X_CHAIN
)
x_avalanche_address_hash: str = AvalancheAddress.decode(
    address=x_avalanche_address, address_type=Avalanche.ADDRESS_TYPES.X_CHAIN
)
print("(X-Chain) Avalanche Address:", x_avalanche_address, x_avalanche_address_hash)

eos_address: str = EOSAddress.encode(public_key=public_key)
eos_public_key: str = EOSAddress.decode(address=eos_address)
print("EOS Address:", eos_address, eos_public_key)

p2pkh_ergo_address: str = ErgoAddress.encode(
    public_key=public_key, network_type="testnet", address_type=Ergo.ADDRESS_TYPES.P2PKH
)
p2pkh_ergo_public_key: str = ErgoAddress.decode(
    address=p2pkh_ergo_address, network_type="testnet", address_type=Ergo.ADDRESS_TYPES.P2PKH
)
print("(P2PKH) Ergo Address:", p2pkh_ergo_address, p2pkh_ergo_public_key)

p2sh_ergo_address: str = ErgoAddress.encode(
    public_key=public_key, network_type="testnet", address_type=Ergo.ADDRESS_TYPES.P2SH
)
p2sh_ergo_public_key: str = ErgoAddress.decode(
    address=p2sh_ergo_address, network_type="testnet", address_type=Ergo.ADDRESS_TYPES.P2SH
)
print("(P2SH) Ergo Address:", p2sh_ergo_address, p2sh_ergo_public_key)

icon_address: str = IconAddress.encode(public_key=public_key)
icon_address_hash: str = IconAddress.decode(address=icon_address)
print("Icon Address:", icon_address, icon_address_hash)

okt_chain_address: str = OKTChainAddress.encode(
    public_key=public_key, hrp=OKTChain.NETWORKS.MAINNET.HRP
)
okex_chain_address_hash: str = OKTChainAddress.decode(
    address=okt_chain_address, hrp=OKTChain.NETWORKS.MAINNET.HRP
)
print("OKEx-Chain Address:", okt_chain_address, okex_chain_address_hash)

harmony_address: str = HarmonyAddress.encode(
    public_key=public_key, hrp=Harmony.NETWORKS.MAINNET.HRP
)
harmony_address_hash: str = HarmonyAddress.decode(
    address=harmony_address, hrp=Harmony.NETWORKS.MAINNET.HRP
)
print("Harmony Address:", harmony_address, harmony_address_hash)

zilliqa_address: str = ZilliqaAddress.encode(
    public_key=public_key, hrp=Zilliqa.NETWORKS.MAINNET.HRP
)
zilliqa_address_hash: str = ZilliqaAddress.decode(
    address=zilliqa_address, hrp=Zilliqa.NETWORKS.MAINNET.HRP
)
print("Zilliqa Address:", zilliqa_address, zilliqa_address_hash)

injective_address: str = InjectiveAddress.encode(
    public_key=public_key, hrp=Injective.NETWORKS.MAINNET.HRP
)
injective_address_hash: str = InjectiveAddress.decode(
    address=injective_address, hrp=Injective.NETWORKS.MAINNET.HRP
)
print("Injective Address:", injective_address, injective_address_hash)
