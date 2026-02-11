import contextlib
import pytest

from hdwallet.exceptions import MnemonicError
from hdwallet.mnemonics.imnemonic import (
     Trie, WordIndices,
)
from hdwallet.mnemonics.slip39.mnemonic import (
    SLIP39Mnemonic, language_parser, group_parser,
)

import shamir_mnemonic


def test_slip39_language():

    # Any name; no spec --> simplest 1/1 group encoding yielding single mnemonic
    spec = language_parser("english")
    assert spec == {
        ("english",(1,1)): {
            0: (1,1),
        },
    }

    # No name or secret spec, and a single group w/ default size based on group threshold
    group = group_parser("Name 3 / ", size_default=None)
    assert group == ("Name",(3,6))
    spec = language_parser(": Name 3 / ")
    assert spec == {
        ("",(1,1)): {
            "Name": (3,6),
        },
    }

    # A secret w/ threshold 3 required, of the default 4 groups of fibonacci required mnemonics
    for language in [
        " 3 / 4 ",
        " 3 / 4 [ ] ",
        " 3 / : ,,, ",
        " 3 / : 1/, 1, 4, 3/ ",
    ]:
        spec = language_parser(language)
        assert spec == {
            ("",(3,4)): {
                0: (1,1),
                1: (1,1),
                2: (2,4),
                3: (3,6),
            },
        }, f"Language {language} yielded incorrect encoding: {spec!r}"

    # If some group specs are provided, the rest are deduced in a fibonacci-ish sequence
    spec = language_parser("Satoshi Nakamoto 7 [ 2/3 ] ")
    assert spec == {
        ("Satoshi Nakamoto",(4,7)): {
            0: (2,3),
            1: (1,1),
            2: (3,6),
            3: (4,8),
            4: (7,14),
            5: (8,16),
            6: (8,16),
        },
    }

    assert language_parser("Fibonacci Defaults 3 / 5") == {
        ("Fibonacci Defaults",(3,5)): {
            0: (1,1),
            1: (1,1),
            2: (2,4),
            3: (3,6),
            4: (5,10),
        },
    }

def test_slip39_mnemonics():

    # Ensure our prefix and whitespace handling works correctly
    assert SLIP39Mnemonic.NORMALIZE.match(
        "  Group 1 { word word"
    ).groups() == ("Group 1 {","word word")

    assert SLIP39Mnemonic.NORMALIZE.match(
        "  Group 1 { word word  "
    ).groups() == ("Group 1 {","word word")

    assert SLIP39Mnemonic.NORMALIZE.match(
        "            word word  "
    ).groups() == (None,"word word")

    assert SLIP39Mnemonic.NORMALIZE.match(
        "  Group 1 {   "
    ).groups() == ("Group 1 {",None)

    entropy = "ff"*(256//8)
    mnemonic = SLIP39Mnemonic.encode(entropy=entropy, language="")
    mnemonic_list = SLIP39Mnemonic.normalize(mnemonic)
    recovered = SLIP39Mnemonic.decode(mnemonic_list)
    assert recovered == entropy

    expected_entropy = "ff" * (512 // 8)  # 64 bytes of 0xFF

    slip39 = SLIP39Mnemonic(mnemonic)
    assert slip39._mnemonic == mnemonic_list
    assert slip39.mnemonic() == mnemonic

    for mnemonic in [
        "curly agency academic academic academic boring radar cluster domestic ticket fumes remove velvet fluff video crazy chest average script universe exhaust remind helpful lamp declare garlic repeat unknown bucket adorn sled adult triumph source divorce premium genre glimpse level listen ancestor wildlife writing document wrist judicial medical detect frost leaves language jerky increase glasses extra alto burden iris swing",
        "trend cleanup acrobat easy acid military timber boundary museum dictate argue always grasp bundle welcome silent campus exhaust snake magazine kitchen surface unfold theory adequate gasoline exotic counter fantasy magazine slow mailman metric thumb listen ruler elite mansion diet hybrid withdraw swing makeup repeat glasses density express ting estimate climate scholar loyalty unfold bumpy ecology briefing much fiscal mental\ntrend cleanup beard easy acne extra profile window craft custody owner plot inherit injury starting iris talent curious squeeze retreat density decision hush rainbow extra grumpy humidity income should spray elevator drove large source game pajamas sprinkle dining security class adapt credit therapy verify realize retailer scatter suitable stick hearing lecture mountain dragon talent medal decision equip cleanup aircraft",
        "salon email acrobat romp acid lunar rival view daughter exchange privacy pickup moisture forbid welcome amount estimate therapy sled theory says member scroll sister smell erode scene tension glance laden ting cricket apart senior legend transfer describe crowd exceed saver lilac episode cluster pipeline sniff window loyalty manual behavior raspy problem fraction story playoff scroll aunt benefit element execute\nsalon email beard romp acquire vocal plan aviation nervous package unhappy often goat forward closet material fortune fitness wireless terminal slap resident aunt artist source cover perfect grant military ruin taught depend criminal theater decision standard salary priority equation license prisoner rhyme indicate academic shaft express kernel airport tolerate market owner erode dance orange beaver distance smug plunge level\nsalon email ceramic roster academic spark starting says phantom tension saver erode ugly smoking crazy screw pumps display funding fortune mixture ancestor industry glad paces junk laden timber hunting secret program ruin gather clogs legal sugar adjust check crazy genuine predator national swimming twice admit desert system sidewalk check class spelling early morning liberty grief election antenna merchant adjust\nsalon email ceramic scared acid cultural object wildlife percent include wealthy geology capture lift evidence envy identify game guilt curly garbage reaction early scatter practice metric mild earth subject axis verdict juice sled dominant ranked blimp sympathy credit example typical float prisoner ting paces husband adequate amuse display worthy amuse depict civil learn modify lecture mother paid evil stadium\nsalon email ceramic shadow acquire critical ugly desire piece romp piece olympic benefit cargo forbid superior credit username library usher beyond include verify pipeline volume pistol ajar mild carbon acrobat receiver decrease champion calcium flea email picture funding tracks junior fishing thorn regret lily tofu decent romp hazard loud cards peaceful alien retreat single pregnant unfold trial wrist jury\nsalon email ceramic sister acne spirit parking aquatic phrase fact order racism tendency example disaster finance trip multiple ranked lobe tackle smirk regular auction satoshi elephant traveler estimate practice sprinkle true making manual adjust herald mama jacket fishing lecture volume phantom symbolic liberty usher moment alcohol born nervous flip desert element budget pink switch envy discuss laden check promise\nsalon email decision round acquire voting damage briefing emphasis parking airport nylon umbrella coding fake cylinder chubby bolt superior client shame museum reward domain briefing forget guilt group leaf teacher that remind blind judicial soul library dismiss guard provide smoking robin blue focus relate tricycle flexible meaning painting venture trip manager stay flexible rebuild group elephant papa dismiss activity\nsalon email decision scatter acid idle veteran knife thorn theory remember volume cluster writing drove process staff usual sprinkle observe sympathy says birthday lunar leaves salary belong license submit anxiety award spray body victim domestic solution decent geology huge preach human scared desktop email frost verify says predator debris peasant burden swing owner safari reaction broken glimpse jacket deal\nsalon email decision shaft academic breathe mental capital midst guest tracks bolt twin change usual rescue profile taxi paces penalty vitamins emphasis story acquire exhaust salt quantity junction shame midst saver peanut acquire trash duke spend remember predator miracle vintage rich multiple story inmate depend example together blimp coding depart acid diminish petition sister mountain explain thumb density kidney\nsalon email decision skin acne owner finance kernel deal crazy fortune kernel cause warn ordinary document forward alto mixed burning theater axis hybrid review squeeze force shelter owner minister jump darkness smith advance greatest stadium listen prune prisoner exceed medal hospital else race lying liquid tolerate preach capture therapy junction method demand glasses relate emerald blind club income exceed\nsalon email decision snake acne repair sidewalk window video knit resident alien window weapon chubby pacific segment artwork nuclear erode thorn replace wits snapshot founder shaped quiet spray sled depend decent cage income pecan estimate purchase frequent trash chew luxury glimpse category move pipeline scout snake source entrance laundry skunk gravity briefing ancestor hormone security husky snake nylon prospect\nsalon email decision spider academic dramatic axis overall finger early alive health decent ceiling explain capture deploy trip mother viral valid unwrap filter holiday saver fake sharp decorate mustang stay survive hybrid hybrid cowboy peanut that findings umbrella worthy venture quick various watch filter impact jury paid elevator retreat literary viral capacity skin bumpy blue criminal behavior surface legal",
    ]:
        assert SLIP39Mnemonic.is_valid(mnemonic)
        slip39 = SLIP39Mnemonic(mnemonic)
        assert slip39.words() == 59
        assert SLIP39Mnemonic.decode(slip39.mnemonic()) == expected_entropy

        # Let's make sure we can detect missing mnemonics reliably.  With random subsets, we should
        # either decode the Mnemonic, or get a MnemonicError detailing what was missing
        mnemonic_list = mnemonic.split('\n')
        import random

        # Start with full list size and decrease
        for subset_size in range(len(mnemonic_list), 0, -1):
            # Create random subset
            subset = random.sample(mnemonic_list, subset_size)

            try:
                result = SLIP39Mnemonic.decode( '\n'.join(subset) )

                # If decode succeeds, verify it returns expected entropy
                assert result == expected_entropy, (
                    f"Subset size {subset_size}: Expected entropy {expected_entropy}, "
                    f"got {result}"
                )
            except MnemonicError as e:
                # Verify it's the expected "Incomplete" error
                assert "Incomplete: found" in str(e), (
                    f"Subset size {subset_size}: Expected 'Incomplete; found' error, "
                    f"got: {str(e)}"
                )
            except Exception as e:
                # Unexpected error type
                pytest.fail(
                    f"Subset size {subset_size}: Unexpected error type {type(e)}: {e}"
                )


class substitute( contextlib.ContextDecorator ):
    """The SLIP-39 standard includes random data in portions of the as share.  Replace the random
    function during testing to get determinism in resultant nmenomics.

    """
    def __init__( self, thing, attribute, value ):
        self.thing		= thing
        self.attribute		= attribute
        self.value		= value
        self.saved		= None

    def __enter__( self ):
        self.saved		= getattr( self.thing, self.attribute )
        setattr( self.thing, self.attribute, self.value )

    def __exit__( self, *exc ):
        setattr( self.thing, self.attribute, self.saved )


@substitute( shamir_mnemonic.shamir, 'RANDOM_BYTES', lambda n: b'\0' * n )
def test_slip39_tabulate():
    """Details of the SLIP-39 specifications' 'language' and output 'tabulate' value must be kept,
    so .mnemonic() reflects them.

    """

    entropy_128 = "ff"*(128//8)
    entropy_256 = "ff"*(256//8)
    entropy_512 = "ff"*(512//8)



    family = "Perry Kundert [ One 1/1, Two 1/1, Fam 2/4, Frens 3/6 ]"
    family_tabulate_None = """\
One 1/1    1st  ━  academic  agency  acrobat   romp     course    prune     deadline  umbrella  darkness  salt      bishop    impact    vanish    squeeze   moment    segment   privacy   bolt      making    enjoy

Two 1/1    1st  ━  academic  agency  beard     romp     downtown  inmate    hamster   counter   rainbow   grocery   veteran   decorate  describe  bedroom   disease   suitable  peasant   editor    welfare   spider

Fam 2/4    1st  ┳  academic  agency  ceramic   roster   crystal   critical  forbid    sled      building  glad      legs      angry     enlarge   ting      ranked    round     solution  legend    ending    lips
                ╏
           2nd  ┣  academic  agency  ceramic   scared   drink     verdict   funding   dragon    activity  verify    fawn      yoga      devote    perfect   jacket    database  picture   genius    process   pipeline
                ╏
           3rd  ┣  academic  agency  ceramic   shadow   avoid     leaf      fantasy   midst     crush     fraction  cricket   taxi      velvet    gasoline  daughter  august    rhythm    excuse    wrist     increase
                ╏
           4th  ┗  academic  agency  ceramic   sister   capital   flexible  favorite  grownup   diminish  sidewalk  yelp      blanket   market    class     testify   temple    silent    prevent   born      galaxy

Frens 3/6  1st  ┳  academic  agency  decision  round    academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  phrase    trust     golden
                ╏
           2nd  ┣  academic  agency  decision  scatter  desert    wisdom    birthday  fatigue   lecture   detailed  destroy   realize   recover   lilac     genre     venture   jacket    mountain  blessing  pulse
                ╏
           3rd  ┣  academic  agency  decision  shaft    birthday  debut     benefit   shame     market    devote    angel     finger    traveler  analysis  pipeline  extra     funding   lawsuit   editor    guilt
                ╏
           4th  ┣  academic  agency  decision  skin     category  skin      alpha     observe   artwork   advance   earth     thank     fact      material  sheriff   peaceful  club      evoke     robin     revenue
                ╏
           5th  ┣  academic  agency  decision  snake    anxiety   acrobat   inform    home      patrol    alpha     erode     steady    cultural  juice     emerald   reject    flash     license   royal     plunge
                ╏
           6th  ┗  academic  agency  decision  spider   earth     woman     gasoline  dryer     civil     deliver   laser     hospital  mountain  wrist     clinic    evidence  database  public    dwarf     lawsuit"""

    family_tabulate_False = """\
academic agency acrobat romp course prune deadline umbrella darkness salt bishop impact vanish squeeze moment segment privacy bolt making enjoy
academic agency beard romp downtown inmate hamster counter rainbow grocery veteran decorate describe bedroom disease suitable peasant editor welfare spider
academic agency ceramic roster crystal critical forbid sled building glad legs angry enlarge ting ranked round solution legend ending lips
academic agency ceramic scared drink verdict funding dragon activity verify fawn yoga devote perfect jacket database picture genius process pipeline
academic agency ceramic shadow avoid leaf fantasy midst crush fraction cricket taxi velvet gasoline daughter august rhythm excuse wrist increase
academic agency ceramic sister capital flexible favorite grownup diminish sidewalk yelp blanket market class testify temple silent prevent born galaxy
academic agency decision round academic academic academic academic academic academic academic academic academic academic academic academic academic phrase trust golden
academic agency decision scatter desert wisdom birthday fatigue lecture detailed destroy realize recover lilac genre venture jacket mountain blessing pulse
academic agency decision shaft birthday debut benefit shame market devote angel finger traveler analysis pipeline extra funding lawsuit editor guilt
academic agency decision skin category skin alpha observe artwork advance earth thank fact material sheriff peaceful club evoke robin revenue
academic agency decision snake anxiety acrobat inform home patrol alpha erode steady cultural juice emerald reject flash license royal plunge
academic agency decision spider earth woman gasoline dryer civil deliver laser hospital mountain wrist clinic evidence database public dwarf lawsuit"""

    assert SLIP39Mnemonic.encode(entropy=entropy_128, language=family, tabulate=None) == family_tabulate_None
    assert SLIP39Mnemonic.encode(entropy=entropy_128, language=family) == family_tabulate_False

    # Now, ensure that a SLIP39Mnemonic instance remembers its SLIP-39 encoding parameters and desired tabulation.
    slip39 = SLIP39Mnemonic(mnemonic=family_tabulate_False, language=family, tabulate=None)
    assert slip39.mnemonic() == family_tabulate_None



    assert SLIP39Mnemonic.encode(entropy=entropy_512, language=family, tabulate=None) == """\
One 1/1    1st  ━  academic  agency  acrobat   romp     acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle      kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis    firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill

Two 1/1    1st  ━  academic  agency  beard     romp     acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific   deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics

Fam 2/4    1st  ┳  academic  agency  ceramic   roster   academic  lyrics    envelope  tendency  flexible  careful   shelter   often     plunge    headset   educate   freshman  isolate   flea      receiver  hunting   training  tricycle  legal     snapshot  rainbow   pencil    enforce   priority  spine     hesitate  civil     scandal   makeup    privacy   vitamins  platform  inherit   sheriff   relate    evil      breathe   lilac     vitamins  theater   render    patrol    airport   vitamins  clogs     hour      standard  sugar     exceed    shadow    laundry   involve   ticket    public    cargo
                ╏
           2nd  ┣  academic  agency  ceramic   scared   academic  western   unknown   daughter  valid     satisfy   remember  toxic     chubby    various   become    pile      craft     taste     group     listen    amazing   phantom   rescue    sugar     patrol    require   discuss   amazing   software  guitar    race      observe   window    medical   sister    fatal     else      species   mule      hesitate  formal    flash     steady    isolate   express   repair    fangs     expand    likely    fumes     evoke     champion  screw     space     imply     dive      yoga      ordinary  rebound
                ╏
           3rd  ┣  academic  agency  ceramic   shadow   academic  harvest   rebuild   knit      beard     pickup    corner    clogs     payroll   detailed  tendency  ultimate  sugar     earth     pharmacy  wits      deploy    capacity  fiction   aide      observe   very      breathe   genre     swing     ancient   arcade    juice     guest     leaves    mixture   superior  born      wavy      endorse   lying     omit      coding    angry     bishop    evening   yelp      pitch     satoshi   impact    avoid     username  practice  easy      wavy      scout     credit    emperor   physics   crazy
                ╏
           4th  ┗  academic  agency  ceramic   sister   academic  browser   axle      quantity  recover   junk      float     forbid    criminal  premium   puny      boundary  mama      regret    intimate  body      spark     false     hour      aunt      march     typical   grumpy    scene     strategy  award     observe   clinic    bucket    parcel    pink      charity   clothes   that      hand      platform  syndrome  video     clay      medical   rhythm    tracks    writing   junior    spew      dynamic   health    eyebrow   silent    theater   shadow    grasp     garbage   mandate   length

Frens 3/6  1st  ┳  academic  agency  decision  round    academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  fragment  receiver  provide
                ╏
           2nd  ┣  academic  agency  decision  scatter  academic  wealthy   health    losing    moisture  display   damage    scout     junk      roster    percent   society   income    lying     bolt      again     privacy   visual    firm      infant    coal      lawsuit   scout     eraser    campus    alpha     force     fragment  obtain    very      acquire   firefly   eyebrow   judicial  primary   pecan     entrance  counter   snake     parking   anxiety   general   strategy  manual    wireless  provide   timber    level     warn      join      frost     episode   primary   percent   maximum
                ╏
           3rd  ┣  academic  agency  decision  shaft    acquire   likely    unfair    grill     course    news      fake      bulge     trip      drift     treat     news      manual    corner    game      depart    item      devote    writing   taste     cleanup   leaves    taste     jewelry   speak     fumes     darkness  spider    execute   canyon    legs      unfair    sniff     tackle    actress   laden     kernel    rhythm    smear     ranked    regular   describe  cause     bike      snapshot  scandal   sniff     dress     aspect    task      kidney    wrote     junction  pistol    suitable
                ╏
           4th  ┣  academic  agency  decision  skin     acquire   junction  lobe      teammate  require   pajamas   laser     talent    mild      wits      exclude   entrance  yield     pants     epidemic  dilemma   sprinkle  roster    pink      prayer    admit     yelp      building  depend    slim      floral    inherit   luxury    spirit    unhappy   lecture   resident  legend    picture   pregnant  strategy  depict    museum    carpet    biology   quarter   filter    webcam    paid      crisis    industry  desktop   rhyme     vitamins  pharmacy  charity   receiver  mama      research  ticket
                ╏
           5th  ┣  academic  agency  decision  snake    acne      intimate  empty     treat     agency    ceiling   destroy   industry  river     machine   editor    standard  prospect  alarm     spider    security  aquatic   satisfy   rapids    inform    very      threaten  withdraw  market    desktop   furl      devote    squeeze   anxiety   lamp      patrol    oasis     grill     regret    artwork   downtown  invasion  shadow    grant     pecan     tidy      gray      credit    amazing   expand    secret    trip      mixed     perfect   remind    best      lobe      adult     airport   penalty
                ╏
           6th  ┗  academic  agency  decision  spider   acne      memory    daisy     humidity  nail      bucket    burden    puny      scandal   epidemic  tidy      alarm     satoshi   medal     safari    saver     party     detailed  taxi      acid      spine     obtain    dive      seafood   cradle    focus     heat      makeup    method    mason     patent    sister    dictate   rumor     pajamas   package   early     teammate  race      ajar      unhappy   agency    very      lips      railroad  invasion  avoid     away      frost     romp      exotic    smear     vegan     bolt      nylon"""

    assert SLIP39Mnemonic.encode(entropy=entropy_512, language=family, tabulate=True) == """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                └  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill

Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                └  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics

Fam 2/4    1st  ┳  academic  agency    ceramic   roster    academic  lyrics    envelope  tendency  flexible  careful   shelter   often     plunge    headset   educate   freshman  isolate   flea      receiver  hunting
                ├  training  tricycle  legal     snapshot  rainbow   pencil    enforce   priority  spine     hesitate  civil     scandal   makeup    privacy   vitamins  platform  inherit   sheriff   relate    evil
                └  breathe   lilac     vitamins  theater   render    patrol    airport   vitamins  clogs     hour      standard  sugar     exceed    shadow    laundry   involve   ticket    public    cargo
                ╏
           2nd  ┣  academic  agency    ceramic   scared    academic  western   unknown   daughter  valid     satisfy   remember  toxic     chubby    various   become    pile      craft     taste     group     listen
                ├  amazing   phantom   rescue    sugar     patrol    require   discuss   amazing   software  guitar    race      observe   window    medical   sister    fatal     else      species   mule      hesitate
                └  formal    flash     steady    isolate   express   repair    fangs     expand    likely    fumes     evoke     champion  screw     space     imply     dive      yoga      ordinary  rebound
                ╏
           3rd  ┣  academic  agency    ceramic   shadow    academic  harvest   rebuild   knit      beard     pickup    corner    clogs     payroll   detailed  tendency  ultimate  sugar     earth     pharmacy  wits
                ├  deploy    capacity  fiction   aide      observe   very      breathe   genre     swing     ancient   arcade    juice     guest     leaves    mixture   superior  born      wavy      endorse   lying
                └  omit      coding    angry     bishop    evening   yelp      pitch     satoshi   impact    avoid     username  practice  easy      wavy      scout     credit    emperor   physics   crazy
                ╏
           4th  ┣  academic  agency    ceramic   sister    academic  browser   axle      quantity  recover   junk      float     forbid    criminal  premium   puny      boundary  mama      regret    intimate  body
                ├  spark     false     hour      aunt      march     typical   grumpy    scene     strategy  award     observe   clinic    bucket    parcel    pink      charity   clothes   that      hand      platform
                └  syndrome  video     clay      medical   rhythm    tracks    writing   junior    spew      dynamic   health    eyebrow   silent    theater   shadow    grasp     garbage   mandate   length

Frens 3/6  1st  ┳  academic  agency    decision  round     academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                ├  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                └  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic  fragment  receiver  provide
                ╏
           2nd  ┣  academic  agency    decision  scatter   academic  wealthy   health    losing    moisture  display   damage    scout     junk      roster    percent   society   income    lying     bolt      again
                ├  privacy   visual    firm      infant    coal      lawsuit   scout     eraser    campus    alpha     force     fragment  obtain    very      acquire   firefly   eyebrow   judicial  primary   pecan
                └  entrance  counter   snake     parking   anxiety   general   strategy  manual    wireless  provide   timber    level     warn      join      frost     episode   primary   percent   maximum
                ╏
           3rd  ┣  academic  agency    decision  shaft     acquire   likely    unfair    grill     course    news      fake      bulge     trip      drift     treat     news      manual    corner    game      depart
                ├  item      devote    writing   taste     cleanup   leaves    taste     jewelry   speak     fumes     darkness  spider    execute   canyon    legs      unfair    sniff     tackle    actress   laden
                └  kernel    rhythm    smear     ranked    regular   describe  cause     bike      snapshot  scandal   sniff     dress     aspect    task      kidney    wrote     junction  pistol    suitable
                ╏
           4th  ┣  academic  agency    decision  skin      acquire   junction  lobe      teammate  require   pajamas   laser     talent    mild      wits      exclude   entrance  yield     pants     epidemic  dilemma
                ├  sprinkle  roster    pink      prayer    admit     yelp      building  depend    slim      floral    inherit   luxury    spirit    unhappy   lecture   resident  legend    picture   pregnant  strategy
                └  depict    museum    carpet    biology   quarter   filter    webcam    paid      crisis    industry  desktop   rhyme     vitamins  pharmacy  charity   receiver  mama      research  ticket
                ╏
           5th  ┣  academic  agency    decision  snake     acne      intimate  empty     treat     agency    ceiling   destroy   industry  river     machine   editor    standard  prospect  alarm     spider    security
                ├  aquatic   satisfy   rapids    inform    very      threaten  withdraw  market    desktop   furl      devote    squeeze   anxiety   lamp      patrol    oasis     grill     regret    artwork   downtown
                └  invasion  shadow    grant     pecan     tidy      gray      credit    amazing   expand    secret    trip      mixed     perfect   remind    best      lobe      adult     airport   penalty
                ╏
           6th  ┣  academic  agency    decision  spider    acne      memory    daisy     humidity  nail      bucket    burden    puny      scandal   epidemic  tidy      alarm     satoshi   medal     safari    saver
                ├  party     detailed  taxi      acid      spine     obtain    dive      seafood   cradle    focus     heat      makeup    method    mason     patent    sister    dictate   rumor     pajamas   package
                └  early     teammate  race      ajar      unhappy   agency    very      lips      railroad  invasion  avoid     away      frost     romp      exotic    smear     vegan     bolt      nylon"""
    
    mnemonics = SLIP39Mnemonic.encode(entropy=entropy_512, language=family, tabulate=10)
    assert mnemonics == """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction
                ├  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest
                ├  prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                ├  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge
                └  invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill

Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid
                ├  likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk
                ├  gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                ├  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy
                └  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics

Fam 2/4    1st  ┳  academic  agency    ceramic   roster    academic  lyrics    envelope  tendency  flexible  careful
                ├  shelter   often     plunge    headset   educate   freshman  isolate   flea      receiver  hunting
                ├  training  tricycle  legal     snapshot  rainbow   pencil    enforce   priority  spine     hesitate
                ├  civil     scandal   makeup    privacy   vitamins  platform  inherit   sheriff   relate    evil
                ├  breathe   lilac     vitamins  theater   render    patrol    airport   vitamins  clogs     hour
                └  standard  sugar     exceed    shadow    laundry   involve   ticket    public    cargo
                ╏
           2nd  ┣  academic  agency    ceramic   scared    academic  western   unknown   daughter  valid     satisfy
                ├  remember  toxic     chubby    various   become    pile      craft     taste     group     listen
                ├  amazing   phantom   rescue    sugar     patrol    require   discuss   amazing   software  guitar
                ├  race      observe   window    medical   sister    fatal     else      species   mule      hesitate
                ├  formal    flash     steady    isolate   express   repair    fangs     expand    likely    fumes
                └  evoke     champion  screw     space     imply     dive      yoga      ordinary  rebound
                ╏
           3rd  ┣  academic  agency    ceramic   shadow    academic  harvest   rebuild   knit      beard     pickup
                ├  corner    clogs     payroll   detailed  tendency  ultimate  sugar     earth     pharmacy  wits
                ├  deploy    capacity  fiction   aide      observe   very      breathe   genre     swing     ancient
                ├  arcade    juice     guest     leaves    mixture   superior  born      wavy      endorse   lying
                ├  omit      coding    angry     bishop    evening   yelp      pitch     satoshi   impact    avoid
                └  username  practice  easy      wavy      scout     credit    emperor   physics   crazy
                ╏
           4th  ┣  academic  agency    ceramic   sister    academic  browser   axle      quantity  recover   junk
                ├  float     forbid    criminal  premium   puny      boundary  mama      regret    intimate  body
                ├  spark     false     hour      aunt      march     typical   grumpy    scene     strategy  award
                ├  observe   clinic    bucket    parcel    pink      charity   clothes   that      hand      platform
                ├  syndrome  video     clay      medical   rhythm    tracks    writing   junior    spew      dynamic
                └  health    eyebrow   silent    theater   shadow    grasp     garbage   mandate   length

Frens 3/6  1st  ┳  academic  agency    decision  round     academic  academic  academic  academic  academic  academic
                ├  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                ├  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                ├  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                ├  academic  academic  academic  academic  academic  academic  academic  academic  academic  academic
                └  academic  academic  academic  academic  academic  academic  fragment  receiver  provide
                ╏
           2nd  ┣  academic  agency    decision  scatter   academic  wealthy   health    losing    moisture  display
                ├  damage    scout     junk      roster    percent   society   income    lying     bolt      again
                ├  privacy   visual    firm      infant    coal      lawsuit   scout     eraser    campus    alpha
                ├  force     fragment  obtain    very      acquire   firefly   eyebrow   judicial  primary   pecan
                ├  entrance  counter   snake     parking   anxiety   general   strategy  manual    wireless  provide
                └  timber    level     warn      join      frost     episode   primary   percent   maximum
                ╏
           3rd  ┣  academic  agency    decision  shaft     acquire   likely    unfair    grill     course    news
                ├  fake      bulge     trip      drift     treat     news      manual    corner    game      depart
                ├  item      devote    writing   taste     cleanup   leaves    taste     jewelry   speak     fumes
                ├  darkness  spider    execute   canyon    legs      unfair    sniff     tackle    actress   laden
                ├  kernel    rhythm    smear     ranked    regular   describe  cause     bike      snapshot  scandal
                └  sniff     dress     aspect    task      kidney    wrote     junction  pistol    suitable
                ╏
           4th  ┣  academic  agency    decision  skin      acquire   junction  lobe      teammate  require   pajamas
                ├  laser     talent    mild      wits      exclude   entrance  yield     pants     epidemic  dilemma
                ├  sprinkle  roster    pink      prayer    admit     yelp      building  depend    slim      floral
                ├  inherit   luxury    spirit    unhappy   lecture   resident  legend    picture   pregnant  strategy
                ├  depict    museum    carpet    biology   quarter   filter    webcam    paid      crisis    industry
                └  desktop   rhyme     vitamins  pharmacy  charity   receiver  mama      research  ticket
                ╏
           5th  ┣  academic  agency    decision  snake     acne      intimate  empty     treat     agency    ceiling
                ├  destroy   industry  river     machine   editor    standard  prospect  alarm     spider    security
                ├  aquatic   satisfy   rapids    inform    very      threaten  withdraw  market    desktop   furl
                ├  devote    squeeze   anxiety   lamp      patrol    oasis     grill     regret    artwork   downtown
                ├  invasion  shadow    grant     pecan     tidy      gray      credit    amazing   expand    secret
                └  trip      mixed     perfect   remind    best      lobe      adult     airport   penalty
                ╏
           6th  ┣  academic  agency    decision  spider    acne      memory    daisy     humidity  nail      bucket
                ├  burden    puny      scandal   epidemic  tidy      alarm     satoshi   medal     safari    saver
                ├  party     detailed  taxi      acid      spine     obtain    dive      seafood   cradle    focus
                ├  heat      makeup    method    mason     patent    sister    dictate   rumor     pajamas   package
                ├  early     teammate  race      ajar      unhappy   agency    very      lips      railroad  invasion
                └  avoid     away      frost     romp      exotic    smear     vegan     bolt      nylon"""


    # Now test recovery from the prefixed mnemonics.  First, normalize should work, giving us a
    # straight list of all Mnemonics, of a length divisible by a valid SLIP-39 Mnemonic word length;
    # in this case 59 (for 512-bit secrets).
    import json
    normalized = SLIP39Mnemonic.normalize( mnemonics )
    normalized_json = json.dumps(
        [
            " ".join(normalized[col:col+59])
            for col in range(0,len(normalized),59)
        ], indent=4
    )
    #print( normalized_json )
    assert normalized_json  == """[
    "academic agency acrobat romp acid airport meaning source sympathy junction symbolic lyrics install enjoy remind trend blind vampire type idle kind facility venture image inherit talent burning woman devote guest prevent news rich type unkind clay venture raisin oasis crisis firefly change index hanger belong true floral fawn busy fridge invasion member hesitate railroad campus edge ocean woman spill",
    "academic agency beard romp acid ruler execute bishop tolerate paid likely decent lips carbon exchange saver diminish year credit pacific deliver treat pacific aviation email river paper being deadline hawk gasoline nylon favorite duration spine lungs mixed stadium briefing prisoner fragment submit material fatal ultimate mixture sprinkle genuine educate sympathy anatomy visual carbon station exceed enemy mayor custody lyrics",
    "academic agency ceramic roster academic lyrics envelope tendency flexible careful shelter often plunge headset educate freshman isolate flea receiver hunting training tricycle legal snapshot rainbow pencil enforce priority spine hesitate civil scandal makeup privacy vitamins platform inherit sheriff relate evil breathe lilac vitamins theater render patrol airport vitamins clogs hour standard sugar exceed shadow laundry involve ticket public cargo",
    "academic agency ceramic scared academic western unknown daughter valid satisfy remember toxic chubby various become pile craft taste group listen amazing phantom rescue sugar patrol require discuss amazing software guitar race observe window medical sister fatal else species mule hesitate formal flash steady isolate express repair fangs expand likely fumes evoke champion screw space imply dive yoga ordinary rebound",
    "academic agency ceramic shadow academic harvest rebuild knit beard pickup corner clogs payroll detailed tendency ultimate sugar earth pharmacy wits deploy capacity fiction aide observe very breathe genre swing ancient arcade juice guest leaves mixture superior born wavy endorse lying omit coding angry bishop evening yelp pitch satoshi impact avoid username practice easy wavy scout credit emperor physics crazy",
    "academic agency ceramic sister academic browser axle quantity recover junk float forbid criminal premium puny boundary mama regret intimate body spark false hour aunt march typical grumpy scene strategy award observe clinic bucket parcel pink charity clothes that hand platform syndrome video clay medical rhythm tracks writing junior spew dynamic health eyebrow silent theater shadow grasp garbage mandate length",
    "academic agency decision round academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic academic fragment receiver provide",
    "academic agency decision scatter academic wealthy health losing moisture display damage scout junk roster percent society income lying bolt again privacy visual firm infant coal lawsuit scout eraser campus alpha force fragment obtain very acquire firefly eyebrow judicial primary pecan entrance counter snake parking anxiety general strategy manual wireless provide timber level warn join frost episode primary percent maximum",
    "academic agency decision shaft acquire likely unfair grill course news fake bulge trip drift treat news manual corner game depart item devote writing taste cleanup leaves taste jewelry speak fumes darkness spider execute canyon legs unfair sniff tackle actress laden kernel rhythm smear ranked regular describe cause bike snapshot scandal sniff dress aspect task kidney wrote junction pistol suitable",
    "academic agency decision skin acquire junction lobe teammate require pajamas laser talent mild wits exclude entrance yield pants epidemic dilemma sprinkle roster pink prayer admit yelp building depend slim floral inherit luxury spirit unhappy lecture resident legend picture pregnant strategy depict museum carpet biology quarter filter webcam paid crisis industry desktop rhyme vitamins pharmacy charity receiver mama research ticket",
    "academic agency decision snake acne intimate empty treat agency ceiling destroy industry river machine editor standard prospect alarm spider security aquatic satisfy rapids inform very threaten withdraw market desktop furl devote squeeze anxiety lamp patrol oasis grill regret artwork downtown invasion shadow grant pecan tidy gray credit amazing expand secret trip mixed perfect remind best lobe adult airport penalty",
    "academic agency decision spider acne memory daisy humidity nail bucket burden puny scandal epidemic tidy alarm satoshi medal safari saver party detailed taxi acid spine obtain dive seafood cradle focus heat makeup method mason patent sister dictate rumor pajamas package early teammate race ajar unhappy agency very lips railroad invasion avoid away frost romp exotic smear vegan bolt nylon"
]"""
    # So decode should simply work, ignoring all the Group specification language prefixes and
    # separator/continuation symbols.
    assert SLIP39Mnemonic.decode( mnemonics ) == entropy_512

    # And invalid ones should note why they failed.  First, a valid one:
    assert SLIP39Mnemonic.decode( """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                └  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill

Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                └  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics
        """) == entropy_512

    # Missing last word of 1st Mnemonic (on line 3):
    with pytest.raises(MnemonicError, match="@L3: odd length mnemonic encountered"):
        SLIP39Mnemonic.decode( """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                └  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman

Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                └  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics
        """)

    # Funky lines
    with pytest.raises(MnemonicError, match="@L4: unrecognized mnemonic line"):
        SLIP39Mnemonic.decode( """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                └  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill
# we don't support comments so this Mnemonic will fail due to invalid symbols
Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                └  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics
        """)

    # Bad Mnemonic words
    with pytest.raises(MnemonicError, match="Failed to recover SLIP-39 Mnemonics Invalid mnemonic word 'we'."):
        SLIP39Mnemonic.decode( """\
One 1/1    1st  ┭  academic  agency    acrobat   romp      acid      airport   meaning   source    sympathy  junction  symbolic  lyrics    install   enjoy     remind    trend     blind     vampire   type      idle
                ├  kind      facility  venture   image     inherit   talent    burning   woman     devote    guest     prevent   news      rich      type      unkind    clay      venture   raisin    oasis     crisis
                └  firefly   change    index     hanger    belong    true      floral    fawn      busy      fridge    invasion  member    hesitate  railroad  campus    edge      ocean     woman     spill
# we do not support comments so this Mnemonic will fail due to bad mnemonic words even though it happens to be the right length
# we do not support comments so this Mnemonic will fail due to bad mnemonic words even though it happens to be the right length
# because we purposely expertly accidentally made this line eleven words long
Two 1/1    1st  ┭  academic  agency    beard     romp      acid      ruler     execute   bishop    tolerate  paid      likely    decent    lips      carbon    exchange  saver     diminish  year      credit    pacific
                ├  deliver   treat     pacific   aviation  email     river     paper     being     deadline  hawk      gasoline  nylon     favorite  duration  spine     lungs     mixed     stadium   briefing  prisoner
                └  fragment  submit    material  fatal     ultimate  mixture   sprinkle  genuine   educate   sympathy  anatomy   visual    carbon    station   exceed    enemy     mayor     custody   lyrics
        """)
