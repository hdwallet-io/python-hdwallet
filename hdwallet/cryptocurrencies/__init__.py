#!/usr/bin/env python3

# Copyright © 2020-2025, Meheret Tesfaye Batu <meherett.batu@gmail.com>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from typing import (
    List, Dict, Type
)

from ..exceptions import (
    CryptocurrencyError, SymbolError
)
from .adcoin import Adcoin
from .akashnetwork import AkashNetwork
from .algorand import Algorand
from .anon import Anon
from .aptos import Aptos
from .arbitum import Arbitrum
from .argoneum import Argoneum
from .artax import Artax
from .aryacoin import Aryacoin
from .asiacoin import Asiacoin
from .auroracoin import Auroracoin
from .avalanche import Avalanche
from .avian import Avian
from .axe import Axe
from .axelar import Axelar
from .bandprotocol import BandProtocol
from .base import Base
from .bata import Bata
from .beetlecoin import BeetleCoin
from .belacoin import BelaCoin
from .binance import Binance
from .bismuth import Bismuth
from .bitcloud import BitCloud
from .bitcoin import Bitcoin
from .bitcoinatom import BitcoinAtom
from .bitcoincash import BitcoinCash
from .bitcoincashslp import BitcoinCashSLP
from .bitcoingold import BitcoinGold
from .bitcoingreen import BitcoinGreen
from .bitcoinplus import BitcoinPlus
from .bitcoinprivate import BitcoinPrivate
from .bitcoinsv import BitcoinSV
from .bitcoinz import BitcoinZ
from .bitcore import Bitcore
from .bitsend import BitSend
from .blackcoin import Blackcoin
from .blocknode import Blocknode
from .blockstamp import BlockStamp
from .bolivarcoin import Bolivarcoin
from .britcoin import BritCoin
from .canadaecoin import CanadaECoin
from .cannacoin import Cannacoin
from .cardano import Cardano
from .celo import Celo
from .chihuahua import Chihuahua
from .clams import Clams
from .clubcoin import ClubCoin
from .compcoin import Compcoin
from .cosmos import Cosmos
from .cpuchain import CPUChain
from .cranepay import CranePay
from .crave import Crave
from .dash import Dash
from .deeponion import DeepOnion
from .defcoin import Defcoin
from .denarius import Denarius
from .diamond import Diamond
from .digibyte import DigiByte
from .digitalcoin import Digitalcoin
from .divi import Divi
from .dogecoin import Dogecoin
from .dydx import dYdX
from .ecash import eCash
from .ecoin import ECoin
from .edrcoin import EDRCoin
from .egulden import eGulden
from .einsteinium import Einsteinium
from .elastos import Elastos
from .energi import Energi
from .eos import EOS
from .ergo import Ergo
from .ethereum import Ethereum
from .europecoin import EuropeCoin
from .evrmore import Evrmore
from .exclusivecoin import ExclusiveCoin
from .fantom import Fantom
from .feathercoin import Feathercoin
from .fetchai import FetchAI
from .filecoin import Filecoin
from .firo import Firo
from .firstcoin import Firstcoin
from .fix import FIX
from .flashcoin import Flashcoin
from .flux import Flux
from .foxdcoin import Foxdcoin
from .fujicoin import FujiCoin
from .gamecredits import GameCredits
from .gcrcoin import GCRCoin
from .gobyte import GoByte
from .gridcoin import Gridcoin
from .groestlcoin import GroestlCoin
from .gulden import Gulden
from .harmony import Harmony
from .helleniccoin import Helleniccoin
from .hempcoin import Hempcoin
from .horizen import Horizen
from .huobitoken import HuobiToken
from .hush import Hush
from .icon import Icon
from .injective import Injective
from .insanecoin import InsaneCoin
from .internetofpeople import InternetOfPeople
from .irisnet import IRISnet
from .ixcoin import IXCoin
from .jumbucks import Jumbucks
from .kava import Kava
from .kobocoin import Kobocoin
from .komodo import Komodo
from .landcoin import Landcoin
from .lbrycredits import LBRYCredits
from .linx import Linx
from .litecoin import Litecoin
from .litecoincash import LitecoinCash
from .litecoinz import LitecoinZ
from .lkrcoin import Lkrcoin
from .lynx import Lynx
from .mazacoin import Mazacoin
from .megacoin import Megacoin
from .metis import Metis
from .minexcoin import Minexcoin
from .monacoin import Monacoin
from .monero import Monero
from .monk import Monk
from .multiversx import MultiversX
from .myriadcoin import Myriadcoin
from .namecoin import Namecoin
from .nano import Nano
from .navcoin import Navcoin
from .near import Near
from .neblio import Neblio
from .neo import Neo
from .neoscoin import Neoscoin
from .neurocoin import Neurocoin
from .neutron import Neutron
from .newyorkcoin import NewYorkCoin
from .ninechronicles import NineChronicles
from .nix import NIX
from .novacoin import Novacoin
from .nubits import NuBits
from .nushares import NuShares
from .okcash import OKCash
from .oktchain import OKTChain
from .omni import Omni
from .onix import Onix
from .ontology import Ontology
from .optimism import Optimism
from .osmosis import Osmosis
from .particl import Particl
from .peercoin import Peercoin
from .pesobit import Pesobit
from .phore import Phore
from .pinetwork import PiNetwork
from .pinkcoin import Pinkcoin
from .pivx import Pivx
from .polygon import Polygon
from .poswcoin import PoSWCoin
from .potcoin import Potcoin
from .projectcoin import ProjectCoin
from .putincoin import Putincoin
from .qtum import Qtum
from .rapids import Rapids
from .ravencoin import Ravencoin
from .reddcoin import Reddcoin
from .ripple import Ripple
from .ritocoin import Ritocoin
from .rsk import RSK
from .rubycoin import Rubycoin
from .safecoin import Safecoin
from .saluscoin import Saluscoin
from .scribe import Scribe
from .secret import Secret
from .shadowcash import ShadowCash
from .shentu import Shentu
from .slimcoin import Slimcoin
from .smileycoin import Smileycoin
from .solana import Solana
from .solarcoin import Solarcoin
from .stafi import Stafi
from .stash import Stash
from .stellar import Stellar
from .stratis import Stratis
from .sugarchain import Sugarchain
from .sui import Sui
from .syscoin import Syscoin
from .terra import Terra
from .tezos import Tezos
from .theta import Theta
from .thoughtai import ThoughtAI
from .toacoin import TOACoin
from .tron import Tron
from .twins import TWINS
from .ultimatesecurecash import UltimateSecureCash
from .unobtanium import Unobtanium
from .vcash import Vcash
from .vechain import VeChain
from .verge import Verge
from .vertcoin import Vertcoin
from .viacoin import Viacoin
from .vivo import Vivo
from .voxels import Voxels
from .vpncoin import VPNCoin
from .wagerr import Wagerr
from .whitecoin import Whitecoin
from .wincoin import Wincoin
from .xinfin import XinFin
from .xuez import XUEZ
from .ycash import Ycash
from .zcash import Zcash
from .zclassic import ZClassic
from .zetacoin import Zetacoin
from .zilliqa import Zilliqa
from .zoobc import ZooBC
from .icryptocurrency import ICryptocurrency


class CRYPTOCURRENCIES:

    dictionary: Dict[str, Type[ICryptocurrency]] = {
        Adcoin.NAME: Adcoin,
        AkashNetwork.NAME: AkashNetwork,
        Algorand.NAME: Algorand,
        Anon.NAME: Anon,
        Aptos.NAME: Aptos,
        Arbitrum.NAME: Arbitrum,
        Argoneum.NAME: Argoneum,
        Artax.NAME: Artax,
        Aryacoin.NAME: Aryacoin,
        Asiacoin.NAME: Asiacoin,
        Auroracoin.NAME: Auroracoin,
        Avalanche.NAME: Avalanche,
        Avian.NAME: Avian,
        Axe.NAME: Axe,
        Axelar.NAME: Axelar,
        BandProtocol.NAME: BandProtocol,
        Base.NAME: Base,
        Bata.NAME: Bata,
        BeetleCoin.NAME: BeetleCoin,
        BelaCoin.NAME: BelaCoin,
        Binance.NAME: Binance,
        Bismuth.NAME: Bismuth,
        BitCloud.NAME: BitCloud,
        Bitcoin.NAME: Bitcoin,
        BitcoinAtom.NAME: BitcoinAtom,
        BitcoinCash.NAME: BitcoinCash,
        BitcoinCashSLP.NAME: BitcoinCashSLP,
        BitcoinGold.NAME: BitcoinGold,
        BitcoinGreen.NAME: BitcoinGreen,
        BitcoinPlus.NAME: BitcoinPlus,
        BitcoinPrivate.NAME: BitcoinPrivate,
        BitcoinSV.NAME: BitcoinSV,
        BitcoinZ.NAME: BitcoinZ,
        Bitcore.NAME: Bitcore,
        BitSend.NAME: BitSend,
        Blackcoin.NAME: Blackcoin,
        Blocknode.NAME: Blocknode,
        BlockStamp.NAME: BlockStamp,
        Bolivarcoin.NAME: Bolivarcoin,
        BritCoin.NAME: BritCoin,
        CanadaECoin.NAME: CanadaECoin,
        Cannacoin.NAME: Cannacoin,
        Cardano.NAME: Cardano,
        Celo.NAME: Celo,
        Chihuahua.NAME: Chihuahua,
        Clams.NAME: Clams,
        ClubCoin.NAME: ClubCoin,
        Compcoin.NAME: Compcoin,
        Cosmos.NAME: Cosmos,
        CPUChain.NAME: CPUChain,
        CranePay.NAME: CranePay,
        Crave.NAME: Crave,
        Dash.NAME: Dash,
        DeepOnion.NAME: DeepOnion,
        Defcoin.NAME: Defcoin,
        Denarius.NAME: Denarius,
        Diamond.NAME: Diamond,
        DigiByte.NAME: DigiByte,
        Digitalcoin.NAME: Digitalcoin,
        Divi.NAME: Divi,
        Dogecoin.NAME: Dogecoin,
        dYdX.NAME: dYdX,
        eCash.NAME: eCash,
        ECoin.NAME: ECoin,
        EDRCoin.NAME: EDRCoin,
        eGulden.NAME: eGulden,
        Einsteinium.NAME: Einsteinium,
        Elastos.NAME: Elastos,
        Energi.NAME: Energi,
        EOS.NAME: EOS,
        Ergo.NAME: Ergo,
        Ethereum.NAME: Ethereum,
        EuropeCoin.NAME: EuropeCoin,
        Evrmore.NAME: Evrmore,
        ExclusiveCoin.NAME: ExclusiveCoin,
        Fantom.NAME: Fantom,
        Feathercoin.NAME: Feathercoin,
        FetchAI.NAME: FetchAI,
        Filecoin.NAME: Filecoin,
        Firo.NAME: Firo,
        Firstcoin.NAME: Firstcoin,
        FIX.NAME: FIX,
        Flashcoin.NAME: Flashcoin,
        Flux.NAME: Flux,
        Foxdcoin.NAME: Foxdcoin,
        FujiCoin.NAME: FujiCoin,
        GameCredits.NAME: GameCredits,
        GCRCoin.NAME: GCRCoin,
        GoByte.NAME: GoByte,
        Gridcoin.NAME: Gridcoin,
        GroestlCoin.NAME: GroestlCoin,
        Gulden.NAME: Gulden,
        Harmony.NAME: Harmony,
        Helleniccoin.NAME: Helleniccoin,
        Hempcoin.NAME: Hempcoin,
        Horizen.NAME: Horizen,
        HuobiToken.NAME: HuobiToken,
        Hush.NAME: Hush,
        Icon.NAME: Icon,
        Injective.NAME: Injective,
        InsaneCoin.NAME: InsaneCoin,
        InternetOfPeople.NAME: InternetOfPeople,
        IRISnet.NAME: IRISnet,
        IXCoin.NAME: IXCoin,
        Jumbucks.NAME: Jumbucks,
        Kava.NAME: Kava,
        Kobocoin.NAME: Kobocoin,
        Komodo.NAME: Komodo,
        Landcoin.NAME: Landcoin,
        LBRYCredits.NAME: LBRYCredits,
        Linx.NAME: Linx,
        Litecoin.NAME: Litecoin,
        LitecoinCash.NAME: LitecoinCash,
        LitecoinZ.NAME: LitecoinZ,
        Lkrcoin.NAME: Lkrcoin,
        Lynx.NAME: Lynx,
        Mazacoin.NAME: Mazacoin,
        Megacoin.NAME: Megacoin,
        Metis.NAME: Metis,
        Minexcoin.NAME: Minexcoin,
        Monacoin.NAME: Monacoin,
        Monero.NAME: Monero,
        Monk.NAME: Monk,
        MultiversX.NAME: MultiversX,
        Myriadcoin.NAME: Myriadcoin,
        Namecoin.NAME: Namecoin,
        Nano.NAME: Nano,
        Navcoin.NAME: Navcoin,
        Near.NAME: Near,
        Neblio.NAME: Neblio,
        Neo.NAME: Neo,
        Neoscoin.NAME: Neoscoin,
        Neurocoin.NAME: Neurocoin,
        Neutron.NAME: Neutron,
        NewYorkCoin.NAME: NewYorkCoin,
        NineChronicles.NAME: NineChronicles,
        NIX.NAME: NIX,
        Novacoin.NAME: Novacoin,
        NuBits.NAME: NuBits,
        NuShares.NAME: NuShares,
        OKCash.NAME: OKCash,
        OKTChain.NAME: OKTChain,
        Omni.NAME: Omni,
        Onix.NAME: Onix,
        Ontology.NAME: Ontology,
        Optimism.NAME: Optimism,
        Osmosis.NAME: Osmosis,
        Particl.NAME: Particl,
        Peercoin.NAME: Peercoin,
        Pesobit.NAME: Pesobit,
        Phore.NAME: Phore,
        PiNetwork.NAME: PiNetwork,
        Pinkcoin.NAME: Pinkcoin,
        Pivx.NAME: Pivx,
        Polygon.NAME: Polygon,
        PoSWCoin.NAME: PoSWCoin,
        Potcoin.NAME: Potcoin,
        ProjectCoin.NAME: ProjectCoin,
        Putincoin.NAME: Putincoin,
        Qtum.NAME: Qtum,
        Rapids.NAME: Rapids,
        Ravencoin.NAME: Ravencoin,
        Reddcoin.NAME: Reddcoin,
        Ripple.NAME: Ripple,
        Ritocoin.NAME: Ritocoin,
        RSK.NAME: RSK,
        Rubycoin.NAME: Rubycoin,
        Safecoin.NAME: Safecoin,
        Saluscoin.NAME: Saluscoin,
        Scribe.NAME: Scribe,
        Secret.NAME: Secret,
        ShadowCash.NAME: ShadowCash,
        Shentu.NAME: Shentu,
        Slimcoin.NAME: Slimcoin,
        Smileycoin.NAME: Smileycoin,
        Solana.NAME: Solana,
        Solarcoin.NAME: Solarcoin,
        Stafi.NAME: Stafi,
        Stash.NAME: Stash,
        Stellar.NAME: Stellar,
        Stratis.NAME: Stratis,
        Sugarchain.NAME: Sugarchain,
        Sui.NAME: Sui,
        Syscoin.NAME: Syscoin,
        Terra.NAME: Terra,
        Tezos.NAME: Tezos,
        Theta.NAME: Theta,
        ThoughtAI.NAME: ThoughtAI,
        TOACoin.NAME: TOACoin,
        Tron.NAME: Tron,
        TWINS.NAME: TWINS,
        UltimateSecureCash.NAME: UltimateSecureCash,
        Unobtanium.NAME: Unobtanium,
        Vcash.NAME: Vcash,
        VeChain.NAME: VeChain,
        Verge.NAME: Verge,
        Vertcoin.NAME: Vertcoin,
        Viacoin.NAME: Viacoin,
        Vivo.NAME: Vivo,
        Voxels.NAME: Voxels,
        VPNCoin.NAME: VPNCoin,
        Wagerr.NAME: Wagerr,
        Whitecoin.NAME: Whitecoin,
        Wincoin.NAME: Wincoin,
        XinFin.NAME: XinFin,
        XUEZ.NAME: XUEZ,
        Ycash.NAME: Ycash,
        Zcash.NAME: Zcash,
        ZClassic.NAME: ZClassic,
        Zetacoin.NAME: Zetacoin,
        Zilliqa.NAME: Zilliqa,
        ZooBC.NAME: ZooBC
    }

    @classmethod
    def names(cls) -> List[str]:
        return list(cls.dictionary.keys())

    @classmethod
    def classes(cls) -> List[Type[ICryptocurrency]]:
        return list(cls.dictionary.values())

    @classmethod
    def cryptocurrency(cls, name: str) -> Type[ICryptocurrency]:

        if not cls.is_cryptocurrency(name=name):
            raise CryptocurrencyError(
                "Invalid cryptocurrency name", expected=cls.names(), got=name
            )

        return cls.dictionary[name]

    @classmethod
    def is_cryptocurrency(cls, name: str) -> bool:
        return name in cls.names()


def get_cryptocurrency(symbol: str) -> Type[ICryptocurrency]:
    for cls in CRYPTOCURRENCIES.classes():
        if symbol == cls.SYMBOL:
            return cls
    raise SymbolError(
        f"Cryptocurrency not found with this {symbol} symbol"
    )


__all__: List[str] = [
    "ICryptocurrency", "CRYPTOCURRENCIES", "get_cryptocurrency"
] + [
    cls.__name__ for cls in CRYPTOCURRENCIES.classes()
]
