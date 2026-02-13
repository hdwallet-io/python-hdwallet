# hdwallet/cryptocurrencies/bismuth.py

from typing import Optional, Type, List
from hashlib import sha256
import inspect

from ..consts import Info
from ..eccs import SLIP10Secp256k1ECC
from ..exceptions import CryptocurrencyError
from ..libs.ecc import hash160 as _hash160  # internal HASH160 helper
from .icryptocurrency import ICryptocurrency, INetwork

# ---------------- Address subtypes (per polysign) ----------------

class BISSubType:
    MAINNET_REGULAR   = "MAINNET_REGULAR"
    MAINNET_MULTISIG  = "MAINNET_MULTISIG"
    TESTNET_REGULAR   = "TESTNET_REGULAR"
    TESTNET_MULTISIG  = "TESTNET_MULTISIG"

# Version bytes -> Base58Check prefixes ("Bis1...", "tBis...")
_VERSION_BYTES = {
    BISSubType.MAINNET_REGULAR:  bytes.fromhex("4f545b"),
    BISSubType.MAINNET_MULTISIG: bytes.fromhex("4f54c8"),
    BISSubType.TESTNET_REGULAR:  bytes.fromhex("017ab685"),
    BISSubType.TESTNET_MULTISIG: bytes.fromhex("0146eba5"),
}
_ALL_VERSION_BYTES = set(_VERSION_BYTES.values())

# --------- helpers for network version registries (get_version) ---------

class _FixedVersions:
    def __init__(self, value: int):
        self._value = value
    def get_version(self, *_args, **_kwargs) -> int:
        return self._value

# ---------------- Real network classes ----------------

class BismuthMainnet(INetwork):
    NAME = "mainnet"
    XPRIVATE_KEY_VERSIONS = _FixedVersions(0x0488ADE4)  # xprv
    XPUBLIC_KEY_VERSIONS  = _FixedVersions(0x0488B21E)  # xpub
    WIF_VERSIONS          = _FixedVersions(0x80)
    # NOTE: multi-byte version prefixes
    PUBLIC_KEY_ADDRESS_PREFIX = int.from_bytes(bytes.fromhex("4f545b"), "big")
    SCRIPT_ADDRESS_PREFIX     = int.from_bytes(bytes.fromhex("4f54c8"), "big")

class BismuthTestnet(INetwork):
    NAME = "testnet"
    XPRIVATE_KEY_VERSIONS = _FixedVersions(0x04358394)  # tprv
    XPUBLIC_KEY_VERSIONS  = _FixedVersions(0x043587CF)  # tpub
    WIF_VERSIONS          = _FixedVersions(0xEF)
    PUBLIC_KEY_ADDRESS_PREFIX = int.from_bytes(bytes.fromhex("017ab685"), "big")
    SCRIPT_ADDRESS_PREFIX     = int.from_bytes(bytes.fromhex("0146eba5"), "big")

# ------------------------------ Coin -----------------------------

class Bismuth(ICryptocurrency):
    NAME = "Bismuth"
    SYMBOL = "BIS"
    INFO = Info({
        "SOURCE_CODE": "https://github.com/bismuthfoundation/Bismuth",
        "WHITEPAPER": "https://bismuthcoin.org/pdf/whitepaper.pdf",
        "WEBSITES": [
            "https://bismuthcoin.org",
            "https://bismuth.live"
        ]
    })
    COIN_TYPE = 209
    DEFAULT_PATH = "m/44'/209'/0'/0/{address}"
    ECC = SLIP10Secp256k1ECC  # secp256k1

    class ADDRESSES:
        P2PKH = "P2PKH"
        @classmethod
        def get_addresses(cls) -> List[str]: return [cls.P2PKH]
        @classmethod
        def length(cls) -> int: return 1
        @classmethod
        def names(cls) -> List[str]: return cls.get_addresses()
        @classmethod
        def default(cls) -> str: return cls.P2PKH
        @classmethod
        def has(cls, name: str) -> bool: return name == cls.P2PKH

    DEFAULT_ADDRESS = ADDRESSES.P2PKH

    class MNEMONICS:
        @classmethod
        def get_mnemonics(cls) -> List[str]: return ["BIP39"]

    class SEEDS:
        @classmethod
        def get_seeds(cls) -> List[str]: return ["BIP39"]

    class HDS:
        @classmethod
        def get_hds(cls) -> List[str]: return ["BIP44"]

    class NETWORKS:
        MAINNET: Type[INetwork] = BismuthMainnet
        TESTNET: Type[INetwork] = BismuthTestnet
        _MAP = { "mainnet": MAINNET, "testnet": TESTNET }

        @classmethod
        def is_network(cls, network) -> bool:
            if isinstance(network, str): return network.lower() in cls._MAP
            return inspect.isclass(network) and issubclass(network, INetwork)

        @classmethod
        def get_network(cls, network=None) -> Type[INetwork]:
            if network is None: return cls.MAINNET
            if isinstance(network, str):
                key = network.lower()
                if key in cls._MAP: return cls._MAP[key]
                raise CryptocurrencyError("Unknown Bismuth network",
                                          expected=list(cls._MAP.keys()), got=network)
            if inspect.isclass(network) and issubclass(network, INetwork):
                name = getattr(network, "NAME", "").lower()
                if name in cls._MAP: return cls._MAP[name]
                raise CryptocurrencyError("Unrecognized Bismuth INetwork subclass",
                                          expected=[c.__name__ for c in cls._MAP.values()],
                                          got=getattr(network, "__name__", str(network)))
            raise CryptocurrencyError("Invalid Bismuth network type",
                                      expected=["mainnet","testnet",
                                                BismuthMainnet.__name__, BismuthTestnet.__name__],
                                      got=repr(network))

        @classmethod
        def get_networks(cls) -> List[Type[INetwork]]:
            return [cls.MAINNET, cls.TESTNET]

        @classmethod
        def name_of(cls, network) -> str:
            return cls.get_network(network).NAME

    # --------------------------- Base58 (local, robust) --------------------------

    _B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    _B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}

    @classmethod
    def _b58encode(cls, data: bytes) -> str:
        if not data: return ""
        # leading zeros
        zeros = len(data) - len(data.lstrip(b"\x00"))
        num = int.from_bytes(data, "big")
        enc = bytearray()
        while num > 0:
            num, rem = divmod(num, 58)
            enc.append(cls._B58_ALPHABET[rem])
        enc.extend(b"1" * zeros)
        enc.reverse()
        return enc.decode("ascii")

    @classmethod
    def _b58decode(cls, text: str) -> bytes:
        if not isinstance(text, str): raise TypeError("address must be str")
        raw = text.encode("ascii")
        num = 0
        zeros = 0
        for ch in raw:
            if ch == ord("1"):
                zeros += 1
            else:
                break
        for ch in raw:
            if ch == ord(" "):
                continue
            val = cls._B58_INDEX.get(ch)
            if val is None:
                raise ValueError("invalid base58 character")
            num = num * 58 + val
        # re-encode to bytes; adjust for leading zeros
        full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
        return b"\x00" * zeros + full.lstrip(b"\x00") if full else b"\x00" * zeros

    # --------------------------- public API -----------------------

    @classmethod
    def address_from_public_key(
        cls,
        public_key_bytes: bytes,
        network: Optional[Type[INetwork]] = None,
        *,
        subtype: Optional[str] = None,
        address: Optional[str] = None,
    ) -> str:
        """
        Build a Bismuth ECDSA Base58Check address from a COMPRESSED secp256k1 pubkey.
        """
        # Guard: compressed 33-byte secp256k1 key
        if len(public_key_bytes) != 33 or public_key_bytes[0] not in (0x02, 0x03):
            raise CryptocurrencyError(
                "Bismuth requires a compressed secp256k1 public key (33 bytes, prefix 0x02/0x03)."
            )

        net = cls.NETWORKS.get_network(network)
        kind = address or cls.DEFAULT_ADDRESS
        st = subtype or cls._subtype_from_network_and_kind(net, kind)
        version = cls._version_for(st)

        h160 = _hash160(public_key_bytes)
        payload = version + h160
        checksum = sha256(sha256(payload).digest()).digest()[:4]
        return cls._b58encode(payload + checksum)

    @classmethod
    def _version_for(cls, subtype: str) -> bytes:
        try:
            return _VERSION_BYTES[subtype]
        except KeyError as exc:
            raise CryptocurrencyError(
                "Unknown Bismuth address subtype",
                expected=list(_VERSION_BYTES.keys()),
                got=subtype,
            ) from exc

    @classmethod
    def _subtype_from_network_and_kind(cls, network, _kind: str) -> str:
        # We expose only P2PKH -> regular subtype
        is_test = (cls.NETWORKS.name_of(network) == "testnet")
        return BISSubType.TESTNET_REGULAR if is_test else BISSubType.MAINNET_REGULAR

    @classmethod
    def is_valid_address(cls, addr: str) -> bool:
        """
        Base58Check validator for Bismuth (supports 3- or 4-byte versions).
        """
        if not isinstance(addr, str) or len(addr) < 8:
            return False
        try:
            raw = cls._b58decode(addr)
        except Exception:
            return False

        # Try version lengths we actually use
        for ver_len in (3, 4):
            if len(raw) != ver_len + 20 + 4:
                continue
            version, h160, chksum = raw[:ver_len], raw[ver_len:-4], raw[-4:]
            if version not in _ALL_VERSION_BYTES or len(h160) != 20:
                continue
            calc = sha256(sha256(version + h160).digest()).digest()[:4]
            if calc == chksum:
                return True
        return False
