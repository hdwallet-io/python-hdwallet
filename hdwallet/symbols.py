#!/usr/bin/env python3

# Copyright © 2020-2026, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import List

# Adcoin
ACC: str = "ACC"
# Akash-Network
AKT: str = "AKT"
# Algorand
ALGO: str = "ALGO"
# Anon
ANON: str = "ANON"
# Aptos
APT: str = "APT"
# Arbitrum
ARB: str = "ARB"
# Argoneum
AGM: str = "AGM"
# Artax
XAX: str = "XAX"
# Aryacoin
AYA: str = "AYA"
# Asiacoin
AC: str = "AC"
# Auroracoin
AUR: str = "AUR"
# Avalanche
AVAX: str = "AVAX"
# Avian
AVN: str = "AVN"
# Axe
AXE: str = "AXE"
# Axelar
AXL: str = "AXL"
# Band-Protocol
BAND: str = "BAND"
# Base
BASE: str = "BASE"
# Bata
BTA: str = "BTA"
# Beetle Coin
BEET: str = "BEET"
# Bela Coin
BELA: str = "BELA"
# Binance
BNB: str = "BNB"
# Bit Cloud
BTDX: str = "BTDX"
# Bitcoin
BTC: str = "BTC"
# Bitcoin Atom
BCA: str = "BCA"
# Bitcoin-Cash
BCH: str = "BCH"
# Bitcoin-Cash-SLP
SLP: str = "SLP"
# Bitcoin Gold
BTG: str = "BTG"
# Bitcoin-Green
BITG: str = "BITG"
# Bitcoin Plus
XBC: str = "XBC"
# Bitcoin-Private
BTCP: str = "BTCP"
# Bitcoin SV
BSV: str = "BSV"
# BitcoinZ
BTCZ: str = "BTCZ"
# Bitcore
BTX: str = "BTX"
# Bit Send
BSD: str = "BSD"
# Blackcoin
BLK: str = "BLK"
# Blocknode
BND: str = "BND"
# Block Stamp
BST: str = "BST"
# Bolivarcoin
BOLI: str = "BOLI"
# Brit Coin
BRIT: str = "BRIT"
# Canada eCoin
CDN: str = "CDN"
# Cannacoin
CCN: str = "CCN"
# Cardano
ADA: str = "ADA"
# Celo
CELO: str = "CELO"
# Chihuahua
HUA: str = "HUA"
# Clams
CLAM: str = "CLAM"
# Club Coin
CLUB: str = "CLUB"
# Compcoin
CMP: str = "CMP"
# Cosmos
ATOM: str = "ATOM"
# CPU Chain
CPU: str = "CPU"
# Crane Pay
CRP: str = "CRP"
# Crave
CRAVE: str = "CRAVE"
# Dash
DASH: str = "DASH"
# DeepOnion
ONION: str = "ONION"
# Defcoin
DFC: str = "DFC"
# Denarius
DNR: str = "DNR"
# Diamond
DMD: str = "DMD"
# Digi Byte
DGB: str = "DGB"
# Digitalcoin
DGC: str = "DGC"
# Divi
DIVI: str = "DIVI"
# Dogecoin
DOGE: str = "DOGE"
# dYdX
DYDX: str = "DYDX"
# eCash
XEC: str = "XEC"
# E-coin
ECN: str = "ECN"
# EDR Coin
EDRC: str = "EDRC"
# e-Gulden
EFL: str = "EFL"
# Einsteinium
EMC2: str = "EMC2"
# Elastos
ELA: str = "ELA"
# Energi
NRG: str = "NRG"
# EOS
EOS: str = "EOS"
# Ergo
ERG: str = "ERG"
# Ethereum
ETH: str = "ETH"
# Europe Coin
ERC: str = "ERC"
# Evrmore
EVR: str = "EVR"
# Exclusive Coin
EXCL: str = "EXCL"
# Fantom
FTM: str = "FTM"
# Feathercoin
FTC: str = "FTC"
# Fetch.ai
FET: str = "FET"
# Filecoin
FIL: str = "FIL"
# Firo
FIRO: str = "FIRO"
# Firstcoin
FRST: str = "FRST"
# FIX
FIX: str = "FIX"
# Flashcoin
FLASH: str = "FLASH"
# Flux
FLUX: str = "FLUX"
# Foxdcoin
FOXD: str = "FOXD"
# Fuji Coin
FJC: str = "FJC"
# Game Credits
GAME: str = "GAME"
# GCR Coin
GCR: str = "GCR"
# Go Byte
GBX: str = "GBX"
# Gridcoin
GRC: str = "GRC"
# Groestl Coin
GRS: str = "GRS"
# Gulden
NLG: str = "NLG"
# Harmony
ONE: str = "ONE"
# Helleniccoin
HNC: str = "HNC"
# Hempcoin
THC: str = "THC"
# Horizen
ZEN: str = "ZEN"
# Huobi Token
HT: str = "HT"
# Hush
HUSH: str = "HUSH"
# ICON
ICX: str = "ICX"
# Injective
INJ: str = "INJ"
# InsaneCoin
INSN: str = "INSN"
# Internet Of People
IOP: str = "IOP"
# IRISnet
IRIS: str = "IRIS"
# IX Coin
IXC: str = "IXC"
# Jumbucks
JBS: str = "JBS"
# Kava
KAVA: str = "KAVA"
# Kobocoin
KOBO: str = "KOBO"
# Komodo
KMD: str = "KMD"
# Landcoin
LDCN: str = "LDCN"
# LBRY Credits
LBC: str = "LBC"
# Linx
LINX: str = "LINX"
# Litecoin
LTC: str = "LTC"
# Litecoin Cash
LCC: str = "LCC"
# LitecoinZ
LTZ: str = "LTZ"
# Lkrcoin
LKR: str = "LKR"
# Lynx
LYNX: str = "LYNX"
# Mazacoin
MZC: str = "MZC"
# Megacoin
MEC: str = "MEC"
# Metis
METIS: str = "METIS"
# Minexcoin
MNX: str = "MNX"
# Monacoin
MONA: str = "MONA"
# Monero
XMR: str = "XMR"
# Monk
MONK: str = "MONK"
# MultiversX
EGLD: str = "EGLD"
# Myriadcoin
XMY: str = "XMY"
# Namecoin
NMC: str = "NMC"
# Nano
XNO: str = "XNO"
# Navcoin
NAV: str = "NAV"
# Near
NEAR: str = "NEAR"
# Neblio
NEBL: str = "NEBL"
# Neo
NEO: str = "NEO"
# Neoscoin
NEOS: str = "NEOS"
# Neurocoin
NRO: str = "NRO"
# Neutron
NTRN: str = "NTRN"
# New York Coin
NYC: str = "NYC"
# Nine-Chronicles
NCG: str = "NCG"
# NIX
NIX: str = "NIX"
# Novacoin
NVC: str = "NVC"
# NuBits
NBT: str = "NBT"
# NuShares
NSR: str = "NSR"
# OK Cash
OK: str = "OK"
# OKT-Chain
OKT: str = "OKT"
# Omni
OMNI: str = "OMNI"
# Onix
ONX: str = "ONX"
# Ontology
ONT: str = "ONT"
# Optimism
OP: str = "OP"
# Osmosis
OSMO: str = "OSMO"
# Particl
PART: str = "PART"
# Peercoin
PPC: str = "PPC"
# Pesobit
PSB: str = "PSB"
# Phore
PHR: str = "PHR"
# Pi-Network
PI: str = "PI"
# Pinkcoin
PINK: str = "PINK"
# Pivx
PIVX: str = "PIVX"
# Polygon
MATIC: str = "MATIC"
# PoSW Coin
POSW: str = "POSW"
# Potcoin
POT: str = "POT"
# Project Coin
PRJ: str = "PRJ"
# Putincoin
PUT: str = "PUT"
# Qtum
QTUM: str = "QTUM"
# Rapids
RPD: str = "RPD"
# Ravencoin
RVN: str = "RVN"
# Reddcoin
RDD: str = "RDD"
# Ripple
XRP: str = "XRP"
# Ritocoin
RITO: str = "RITO"
# RSK
RBTC: str = "RBTC"
# Rubycoin
RBY: str = "RBY"
# Safecoin
SAFE: str = "SAFE"
# Saluscoin
SLS: str = "SLS"
# Scribe
SCRIBE: str = "SCRIBE"
# Secret
SCRT: str = "SCRT"
# Shadow Cash
SDC: str = "SDC"
# Shentu
CTK: str = "CTK"
# Slimcoin
SLM: str = "SLM"
# Smileycoin
SMLY: str = "SMLY"
# Solana
SOL: str = "SOL"
# Solarcoin
SLR: str = "SLR"
# Stafi
FIS: str = "FIS"
# Stash
STASH: str = "STASH"
# Stellar
XLM: str = "XLM"
# Stratis
STRAT: str = "STRAT"
# Sugarchain
SUGAR: str = "SUGAR"
# Sui
SUI: str = "SUI"
# Syscoin
SYS: str = "SYS"
# Terra
LUNA: str = "LUNA"
# Tezos
XTZ: str = "XTZ"
# Theta
THETA: str = "THETA"
# Thought AI
THT: str = "THT"
# TOA Coin
TOA: str = "TOA"
# Tron
TRX: str = "TRX"
# TWINS
TWINS: str = "TWINS"
# Ultimate Secure Cash
USC: str = "USC"
# Unobtanium
UNO: str = "UNO"
# Vcash
VC: str = "VC"
# VeChain
VET: str = "VET"
# Verge
XVG: str = "XVG"
# Vertcoin
VTC: str = "VTC"
# Viacoin
VIA: str = "VIA"
# Vivo
VIVO: str = "VIVO"
# Voxels
VOX: str = "VOX"
# Virtual Cash
VASH: str = "VASH"
# Wagerr
WGR: str = "WGR"
# Whitecoin
XWC: str = "XWC"
# Wincoin
WC: str = "WC"
# XinFin
XDC: str = "XDC"
# XUEZ
XUEZ: str = "XUEZ"
# Ycash
YEC: str = "YEC"
# Zcash
ZEC: str = "ZEC"
# ZClassic
ZCL: str = "ZCL"
# Zetacoin
ZET: str = "ZET"
# Zilliqa
ZIL: str = "ZIL"
# ZooBC
ZBC: str = "ZBC"

__all__: List[str] = [
    "ACC",
    "AKT",
    "ALGO",
    "ANON",
    "APT",
    "ARB",
    "AGM",
    "XAX",
    "AYA",
    "AC",
    "AUR",
    "AVAX",
    "AVN",
    "AXE",
    "AXL",
    "BAND",
    "BTA",
    "BEET",
    "BELA",
    "BNB",
    "BTDX",
    "BTC",
    "BCA",
    "BCH",
    "SLP",
    "BTG",
    "BITG",
    "XBC",
    "BTCP",
    "BSV",
    "BTCZ",
    "BTX",
    "BSD",
    "BLK",
    "BND",
    "BST",
    "BOLI",
    "BRIT",
    "CDN",
    "CCN",
    "ADA",
    "CELO",
    "HUA",
    "CLAM",
    "CLUB",
    "CMP",
    "ATOM",
    "CPU",
    "CRP",
    "CRAVE",
    "DASH",
    "ONION",
    "DFC",
    "DNR",
    "DMD",
    "DGB",
    "DGC",
    "DIVI",
    "DOGE",
    "DYDX",
    "XEC",
    "ECN",
    "EDRC",
    "EFL",
    "EMC2",
    "ELA",
    "NRG",
    "EOS",
    "ERG",
    "ETH",
    "ERC",
    "EVR",
    "EXCL",
    "FTM",
    "FTC",
    "FET",
    "FIL",
    "FIRO",
    "FRST",
    "FIX",
    "FLASH",
    "FLUX",
    "FOXD",
    "FJC",
    "GAME",
    "GCR",
    "GBX",
    "GRC",
    "GRS",
    "NLG",
    "ONE",
    "HNC",
    "THC",
    "ZEN",
    "HT",
    "HUSH",
    "ICX",
    "INJ",
    "INSN",
    "IOP",
    "IRIS",
    "IXC",
    "JBS",
    "KAVA",
    "KOBO",
    "KMD",
    "LDCN",
    "LBC",
    "LINX",
    "LTC",
    "LCC",
    "LTZ",
    "LKR",
    "LYNX",
    "MZC",
    "MEC",
    "METIS",
    "MNX",
    "MONA",
    "XMR",
    "MONK",
    "EGLD",
    "XMY",
    "NMC",
    "XNO",
    "NAV",
    "NEAR",
    "NEBL",
    "NEO",
    "NEOS",
    "NRO",
    "NTRN",
    "NYC",
    "NCG",
    "NIX",
    "NVC",
    "NBT",
    "NSR",
    "OK",
    "OKT",
    "OMNI",
    "ONX",
    "ONT",
    "OP",
    "OSMO",
    "PART",
    "PPC",
    "PSB",
    "PHR",
    "PI",
    "PINK",
    "PIVX",
    "MATIC",
    "POSW",
    "POT",
    "PRJ",
    "PUT",
    "QTUM",
    "RPD",
    "RVN",
    "RDD",
    "XRP",
    "RITO",
    "RBTC",
    "RBY",
    "SAFE",
    "SLS",
    "SCRIBE",
    "SCRT",
    "SDC",
    "CTK",
    "SLM",
    "SMLY",
    "SOL",
    "SLR",
    "FIS",
    "STASH",
    "XLM",
    "STRAT",
    "SUGAR",
    "SUI",
    "SYS",
    "LUNA",
    "XTZ",
    "THETA",
    "THT",
    "TOA",
    "TRX",
    "TWINS",
    "USC",
    "UNO",
    "VC",
    "VET",
    "XVG",
    "VTC",
    "VIA",
    "VIVO",
    "VOX",
    "VASH",
    "WGR",
    "XWC",
    "WC",
    "XDC",
    "XUEZ",
    "YEC",
    "ZEC",
    "ZCL",
    "ZET",
    "ZIL",
    "ZBC"
]
