# tests/test_bismuth.py

import pytest

from hdwallet import HDWallet
from hdwallet.hds import BIP44HD
from hdwallet.derivations import BIP44Derivation, CHANGES
from hdwallet.mnemonics import BIP39Mnemonic
from hdwallet.cryptocurrencies import Bismuth

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Deterministic mainnet vectors (P2PKH) for i = 0..4
EXPECTED_MAINNET_P2PKH = [
    "Bis1LenEHPex4WwY3BLxFGRmxNtsvKqgxkSbh",
    "Bis1To2TU8R1Zpu8VHa5S1yindQ9cNEk3z8BG",
    "Bis1WFnMuX97jB2gqF6hV8UUoKxs4zEZA1Vjo",
    "Bis1LYb4s41E3TotifSRfKGZVJ3UfAhLFCYLt",
    "Bis1TzdNTxA8UjjuA4aAn43eTpCobd6BjdFT3",
]

# ----- helpers ---------------------------------------------------

def _wallet_for_index(i: int, network):
    """Build a wallet positioned at the leaf index i..i+1 for the given network."""
    return (
        HDWallet(cryptocurrency=Bismuth, hd=BIP44HD, network=network)
        .from_mnemonic(BIP39Mnemonic(MNEMONIC))
        .from_derivation(
            BIP44Derivation(
                coin_type=Bismuth.COIN_TYPE,
                account=0,
                change=CHANGES.EXTERNAL_CHAIN,
                address=(i, i + 1),
            )
        )
    )

def _leaf_row(hdw) -> dict:
    """Return the deepest row from dumps() (the actual leaf address)."""
    rows = list(hdw.dumps(exclude={"root", "indexes"}))
    assert rows, "no rows returned"
    return max(rows, key=lambda r: r.get("at", {}).get("path", "").count("/"))

def _leaf_address(hdw) -> str:
    return _leaf_row(hdw)["address"]

def _leaf_pubkey_bytes(hdw) -> bytes:
    """Get compressed secp256k1 public key bytes from the current leaf."""
    row = _leaf_row(hdw)
    pk = row.get("public_key") or hdw.public_key()
    if isinstance(pk, (bytes, bytearray)):
        return bytes(pk)
    return bytes.fromhex(pk)

# ----- vectors & structure tests --------------------------------

def test_mainnet_vectors_first5():
    addrs = []
    for i in range(5):
        hdw = _wallet_for_index(i, Bismuth.NETWORKS.MAINNET)
        addrs.append(_leaf_address(hdw))
    assert addrs == EXPECTED_MAINNET_P2PKH

def test_testnet_prefixes_first3():
    addrs = []
    for i in range(3):
        hdw = _wallet_for_index(i, Bismuth.NETWORKS.TESTNET)
        addrs.append(_leaf_address(hdw))
    assert all(a.startswith("tBis") for a in addrs)

def test_network_metadata_present():
    for net in (Bismuth.NETWORKS.MAINNET, Bismuth.NETWORKS.TESTNET):
        for attr in (
            "XPRIVATE_KEY_VERSIONS",
            "XPUBLIC_KEY_VERSIONS",
            "WIF_VERSIONS",
            "PUBLIC_KEY_ADDRESS_PREFIX",
            "SCRIPT_ADDRESS_PREFIX",
        ):
            assert hasattr(net, attr)

# ----- validator & pubkey behavior -------------------------------

def test_validator_accepts_expected_mainnet_addresses():
    for addr in EXPECTED_MAINNET_P2PKH:
        assert Bismuth.is_valid_address(addr)

def test_validator_rejects_bad_checksum():
    hdw = _wallet_for_index(0, Bismuth.NETWORKS.MAINNET)
    addr = _leaf_address(hdw)
    # mutate last character to break Base58Check while staying in charset
    bad = addr[:-1] + ("1" if addr[-1] != "1" else "2")
    assert not Bismuth.is_valid_address(bad)

def test_pubkey_is_compressed_33_bytes():
    hdw = _wallet_for_index(0, Bismuth.NETWORKS.MAINNET)
    pub = _leaf_pubkey_bytes(hdw)
    assert isinstance(pub, (bytes, bytearray))
    assert len(pub) == 33 and pub[0] in (0x02, 0x03)

def test_build_testnet_address_from_pubkey_bytes():
    # Derive once on mainnet, then recompute address on TESTNET using the same pubkey
    hdw = _wallet_for_index(0, Bismuth.NETWORKS.MAINNET)
    pub = _leaf_pubkey_bytes(hdw)

    taddr = Bismuth.address_from_public_key(
        public_key_bytes=pub,
        network=Bismuth.NETWORKS.TESTNET,
    )
    assert isinstance(taddr, str)
    assert taddr.startswith("tBis")
    assert Bismuth.is_valid_address(taddr)
