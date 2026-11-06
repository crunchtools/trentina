"""Decode tables for the encodings garak hides a payload in (#546, gap 23).

Runtime code cannot import ``corpora`` (the garak encoders live there, for the
benchmark and the tests only), so the inverse of garak's Braille and Morse
encoders is written here. ``tests/test_unpack.py`` asserts these round-trip
``corpora.garak_encodings`` exactly, so the two cannot drift.

Both encoders are lossy, so a decode is NOT gated by re-encode equality the way
base64 is (``scan._strict_base64``). Braille shares one cell between a letter
and a digit (told apart by a number-sign prefix) and between some punctuation;
Morse upper-cases and drops anything it has no code for. The gate instead is
the alphabet: a run of Braille cells, or of Morse code groups, is not ordinary
text, and whatever it decodes to must still read as text (``scan._as_text``).
A cell or a code this table does not know makes the whole run decline, so a run
that is not really Braille or Morse is left as it arrived.

The rest of garak's list follows the same rule, each by its own gate:

* **NATO alphabet** is lossy too: garak keeps letters only, spaces included,
  so the decode is one unbroken lower-case run. The gate is a run of code words.
* **Sneaky bits** writes each character's code point in binary with two
  invisible operators and no separator, so a word's bits have more than one
  reading. ``decode_sneaky_bits`` takes the cheapest (letters cheapest), which
  recovers English and Latin text; a script of long code points (CJK) can be
  read wrongly, and then ``_as_text`` usually declines it.
* **Base2048** and **Ecoji** are strict: a decode is re-encoded and must
  reproduce the run, as base64's is. Base2048's tables are the ``base2048``
  package's (MIT, the Rust port of qntm's, which ends with the final bits
  right-aligned and no padding); Ecoji's are the ``ecoji`` package's
  (Apache-2.0, https://github.com/mecforlove/ecoji-py).
* **Zalgo** buries each character under combining marks; the decode drops
  the marks of a character carrying three or more, so an ordinary accent is
  never touched.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

# Letter cells (garak's forward map, inverted). The digit cells below reuse the
# a-j cells, which is why a number sign disambiguates them on the way out.
_LETTER = {
    "⠁": "a", "⠃": "b", "⠉": "c", "⠙": "d", "⠑": "e",
    "⠋": "f", "⠛": "g", "⠓": "h", "⠊": "i", "⠚": "j",
    "⠅": "k", "⠇": "l", "⠍": "m", "⠝": "n", "⠕": "o",
    "⠏": "p", "⠟": "q", "⠗": "r", "⠎": "s", "⠞": "t",
    "⠥": "u", "⠧": "v", "⠺": "w", "⠭": "x", "⠽": "y",
    "⠵": "z",
}  # fmt: skip

_DIGIT = {
    "⠁": "1", "⠃": "2", "⠉": "3", "⠙": "4", "⠑": "5",
    "⠋": "6", "⠛": "7", "⠓": "8", "⠊": "9", "⠚": "0",
}  # fmt: skip

# Two of garak's punctuation cells collide ('.'/'$' on U+2832, '('/')' on
# U+2836). The first key wins; the decode stays readable, which is all L2 needs.
_PUNCT = {
    "⠲": ".", "⠄": "'", "⠂": ",", "⠤": "-", "⠌": "/",
    "⠖": "!", "⠦": "?", "⠒": ":", "⠰": ";", "⠶": "(",
}  # fmt: skip

_NUMBER_SIGN = "⠼"
_CAPITAL_SIGN = "⠠"
_BRAILLE_SPACE = " \n\r\t"


def decode_braille(text: str) -> str | None:
    """garak's Braille, back to text, or None if a cell is unknown."""
    out: list[str] = []
    number = capital = False
    for cell in text:
        if cell in _BRAILLE_SPACE:
            out.append(cell)
            number = capital = False
            continue
        if cell == _NUMBER_SIGN:
            number = True
            continue
        if cell == _CAPITAL_SIGN:
            capital = True
            continue
        char = _DIGIT.get(cell) if number else _LETTER.get(cell) or _PUNCT.get(cell)
        if char is None:
            return None
        out.append(char.upper() if capital else char)
        number = capital = False
    return "".join(out)


# Morse: letters and digits only; a word space is "/", which garak also emits
# for a newline or tab. Unknown codes make the run decline.
_MORSE_CODES = (
    ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - "
    "..- ...- .-- -..- -.-- --.. .---- ..--- ...-- ....- ..... -.... --... ---.. ----. -----"
)
_MORSE = dict(zip(_MORSE_CODES.split(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", strict=True))


def decode_morse(text: str) -> str | None:
    """garak's Morse, back to upper-case text, or None if a code is unknown."""
    out: list[str] = []
    for code in text.split(" "):
        if not code:
            continue
        if code == "/":
            out.append(" ")
            continue
        char = _MORSE.get(code)
        if char is None:
            return None
        out.append(char)
    return "".join(out)


# NATO alphabet: garak's spellings plus the common variants. Longest first in
# the pattern, so ``Juliett`` is never read as ``Juliet`` and a stray ``t``.
_NATO = {
    "alfa": "a", "alpha": "a", "bravo": "b", "charlie": "c", "delta": "d",
    "echo": "e", "foxtrot": "f", "golf": "g", "hotel": "h", "india": "i",
    "juliett": "j", "juliet": "j", "kilo": "k", "lima": "l", "mike": "m",
    "november": "n", "oscar": "o", "papa": "p", "quebec": "q", "romeo": "r",
    "sierra": "s", "tango": "t", "uniform": "u", "victor": "v", "whiskey": "w",
    "whisky": "w", "xray": "x", "x-ray": "x", "yankee": "y", "zulu": "z",
}  # fmt: skip
NATO_WORD = "|".join(sorted((w.replace("-", r"\-") for w in _NATO), key=len, reverse=True))
"""The code words as one regex alternation, for ``scan``'s tokenizer."""


def decode_nato(text: str) -> str | None:
    """A run of NATO code words, back to its letters, or None if one is not."""
    letters: list[str] = []
    for word in text.split():
        letter = _NATO.get(word.lower())
        if letter is None:
            return None
        letters.append(letter)
    return "".join(letters)


# Sneaky bits: U+2062 is a 0, U+2064 a 1, U+200B a space between words.
SNEAKY_ZERO, SNEAKY_ONE, SNEAKY_SPACE = "\u2062", "\u2064", "\u200b"
_SNEAKY_BITS = str.maketrans({SNEAKY_ZERO: "0", SNEAKY_ONE: "1"})
_COMMON_PUNCT = frozenset('.,-:;!?"()/')
_UNREAD = 10**9
_RARE = 9  # a non-ASCII letter or digit: Latin text is the common case
_SYMBOL = 5  # a non-ASCII symbol


def _sneaky_cost(point: int) -> int:
    """What reading ``point`` as one character costs; ``_UNREAD`` if it cannot be one."""
    char = chr(point) if point <= sys.maxunicode else ""
    match char:
        case "":
            cost = _UNREAD
        case _ if char.isalpha():
            cost = 0 if char.isascii() else _RARE
        case "'":
            cost = 0
        case _ if char in _COMMON_PUNCT or char in "\n\t":
            cost = 1
        case _ if char.isdigit():
            cost = 2 if char.isascii() else _RARE
        case _ if char.isprintable() and char != " ":
            cost = 3 if char.isascii() else _SYMBOL
        case _:
            cost = _UNREAD
    return cost


def _sneaky_word(bits: str) -> str | None:
    """The cheapest reading of one word's bits as characters of 4 to 21 bits."""
    size = len(bits)
    best = [0] + [_UNREAD] * size
    back = [0] * (size + 1)
    for start in range(size):
        if best[start] >= _UNREAD or bits[start] != "1":
            continue  # unreachable, or a code point never starts with a 0 bit
        for end in range(start + 4, min(start + 21, size) + 1):
            cost = best[start] + _sneaky_cost(int(bits[start:end], 2)) + 1
            if cost < best[end]:
                best[end], back[end] = cost, start
    if best[size] >= _UNREAD:
        return None
    chars: list[str] = []
    end = size
    while end:
        start = back[end]
        chars.append(chr(int(bits[start:end], 2)))
        end = start
    return "".join(reversed(chars))


def decode_sneaky_bits(text: str) -> str | None:
    """garak's sneaky bits, back to text, or None if a word has no reading."""
    words: list[str] = []
    for word in text.split(SNEAKY_SPACE):
        read = _sneaky_word(word.translate(_SNEAKY_BITS)) if word else ""
        if read is None:
            return None
        words.append(read)
    return " ".join(words)


# Base2048 (11 bits a character) and Ecoji (10 bits an emoji), as the
# ``base2048`` and ``ecoji`` packages write them.
_B2048_BLOCK = (
    "ØµºÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖÙÚÛÜÝÞßàáâãäåæçèéêëìíî"
    "ïðñòóôõöøùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğ"
    "ĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏ"
    "ŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ"
    "ƀƁƂƃƄƅƆƇƈƉƊƋƌƍƎƏƐƑƒƓƔƕƖƗƘƙƚƛƜƝƞƟƠơƢƣƤƥƦƧƨƩƪƫƬƭƮƯ"
    "ưƱƲƳƴƵƶƷƸƹƺƻƼƽƾƿǀǁǂǃǄǅǆǇǈǉǊǋǌǍǎǏǐǑǒǓǔǕǖǗǘǙǚǛǜǝǞǟ"
    "ǠǡǢǣǤǥǦǧǨǩǪǫǬǭǮǯǰǱǲǳǴǵǶǷǸǹǺǻǼǽǾǿȀȁȂȃȄȅȆȇȈȉȊȋȌȍȎȏ"
    "ȐȑȒȓȔȕȖȗȘșȚțȜȝȞȟȠȡȢȣȤȥȦȧȨȩȪȫȬȭȮȯȰȱȲȳȴȵȶȷȸȹȺȻȼȽȾȿ"
    "ɀɁɂɃɄɅɆɇɈɉɊɋɌɍɎɏɐɑɒɓɔɕɖɗɘəɚɛɜɝɞɟɠɡɢɣɤɥɦɧɨɩɪɫɬɭɮɯ"
    "ɰɱɲɳɴɵɶɷɸɹɺɻɼɽɾɿʀʁʂʃʄʅʆʇʈʉʊʋʌʍʎʏʐʑʒʓʔʕʖʗʘʙʚʛʜʝʞʟ"
    "ʠʡʢʣʤʥʦʧʨʩʪʫʬʭʮʯͰͱͲͳͶͷͻͼͽͿΆΈΉΊΌΎΏΐΑΒΓΔΕΖΗΘΙΚΛΜΝΞ"
    "ΟΠΡΣΤΥΦΧΨΩΪΫάέήίΰαβγδεζηθικλμνξοπρςστυφχψωϊϋόύώϏ"
    "ϐϑϒϓϔϕϖϗϘϙϚϛϜϝϞϟϠϡϢϣϤϥϦϧϨϩϪϫϬϭϮϯϰϱϲϳϴϵϷϸϹϺϻϼϽϾϿЀ"
    "ЁЂЃЄЅІЇЈЉЊЋЌЍЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯа"
    "бвгдежзийклмнопрстуфхцчшщъыьэюяѐёђѓєѕіїјљњћќѝўџѠ"
    "ѡѢѣѤѥѦѧѨѩѪѫѬѭѮѯѰѱѲѳѴѵѶѷѸѹѺѻѼѽѾѿҀҁҊҋҌҍҎҏҐґҒғҔҕҖҗҘ"
    "ҙҚқҜҝҞҟҠҡҢңҤҥҦҧҨҩҪҫҬҭҮүҰұҲҳҴҵҶҷҸҹҺһҼҽҾҿӀӁӂӃӄӅӆӇӈ"
    "ӉӊӋӌӍӎӏӐӑӒӓӔӕӖӗӘәӚӛӜӝӞӟӠӡӢӣӤӥӦӧӨөӪӫӬӭӮӯӰӱӲӳӴӵӶӷӸ"
    "ӹӺӻӼӽӾӿԀԁԂԃԄԅԆԇԈԉԊԋԌԍԎԏԐԑԒԓԔԕԖԗԘԙԚԛԜԝԞԟԠԡԢԣԤԥԦԧԨ"
    "ԩԪԫԬԭԮԯԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖաբգ"
    "դեզէըթժիլխծկհձղճմյնշոչպջռսվտրցւփքօֆև؏٠١٢٣٤٥٦٧٨٩۞"
    "۩۰۱۲۳۴۵۶۷۸۹ऄअआइईउऊऋऌऍऎएऐऑऒओऔकखगघङचछजझञटठडढणतथदधन"
    "ऩपफबभमयरऱलळऴवशषसहऽॐॠॡ०१२३४५६७८९ॲॳॴॵॶॷॸॹॺॻॼॽॾॿঀঅআ"
    "ইঈউঊঋঌএঐওঔকখগঘঙচছজঝঞটঠডঢণতথদধনপফবভমযরলশষসহঽৎৠৡ০১"
    "২৩৪৫৬৭৮৯ৰৱ৴৵৶৷৸৹ਅਆਇਈਉਊਏਐਓਔਕਖਗਘਙਚਛਜਝਞਟਠਡਢਣਤਥਦਧਨਪਫ"
    "ਬਭਮਯਰਲਵਸਹੜ੦੧੨੩੪੫੬੭੮੯ੲੳੴઅઆઇઈઉઊઋઌઍએઐઑઓઔકખગઘઙચછજઝઞટ"
    "ઠડઢણતથદધનપફબભમયરલળવશષસહઽૐૠૡ૦૧૨૩૪૫૬૭૮૯ૹଅଆଇଈଉଊଋଌଏଐ"
    "ଓଔକଖଗଘଙଚଛଜଝଞଟଠଡଢଣତଥଦଧନପଫବଭମଯରଲଳଵଶଷସହଽୟୠୡ୦୧୨୩୪୫୬୭"
    "୮୯ୱ୲୳୴୵୶୷ஃஅஆஇஈஉஊஎஏஐஒஓஔகஙசஜஞடணதநனபமயரறலளழவஶஷஸஹௐ௦௧"
    "௨௩௪௫௬௭௮௯௰௱௲௳௴௵௶௷௸௺అఆఇఈఉఊఋఌఎఏఐఒఓఔకఖగఘఙచఛజఝఞటఠడఢణత"
    "థదధనపఫబభమయరఱలళఴవశషసహఽౘౙౚౠౡ౦౧౨౩౪౫౬౭౮౯ಅಆಇಈಉಊಋಌಎಏಐಒ"
    "ಓಔಕಖಗಘಙಚಛಜಝಞಟಠಡಢಣತಥದಧನಪಫಬಭಮಯರಱಲಳವಶಷಸಹಽೞೠೡ೦೧೨೩೪೫೬"
    "೭೮೯ೱೲഅആഇഈഉഊഋഌഎഏഐഒഓഔകഖഗഘങചഛജഝഞടഠഡഢണതഥദധനഩപഫബഭമയരറ"
    "ലളഴവശഷസഹഺഽൠൡ൦൧൨൩൪൫൬൭൮൯൰൱൲൳൴൵ൺൻർൽൾൿඅආඇඈඉඊඋඌඍඎඏඐඑඒ"
    "ඓඔඕඖකඛගඝඞඟචඡජඣඤඥඦටඨඩඪණඬතථදධනඳපඵබභමඹයරලවශෂසහළෆกขฃ"
    "คฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรฤลฦวศษสหฬอฮฯะาเแ"
    "โใไๅ๐๑๒๓๔๕๖๗๘๙ກຂຄງຈຊຍດຕຖທນບປຜຝພຟມຢຣລວສຫອຮຯະາຽເແໂ"
    "ໃໄ໐໑໒໓໔໕໖໗໘໙ໜໝༀ༂༃༓༕༔༖༗༠༡༢༣༤༥༦༧༨༩ཀཁགངཅཆཇཉཊཋཌཎཏཐདན"
    "པཕབམཙཚཛཝཞཟའཡརལཤཥསཧཨཪཫཬ྅ྈྉྊྋ྿࿀࿁࿂࿃࿄࿅࿇࿈࿉࿊࿋࿌࿎࿏࿐࿑࿒࿓࿔႞"
    "႟ကခဂဃငစဆဇဈဉညဋဌဍဎဏတထဒဓနပဖဗဘမယရလဝသဟဠအဢဣဤဥဦဧဨဩဪဿ၀၁၂"
    "၃၄၅၆၇၈၉၊။၌၍၎၏ၐၑၒၓၔၕၚၛၜၝၡၥၦၮၯၰၵၶၷၸၹၺၻၼၽၾၿႀႁႎ႐႑႒႓႔"
    "႕႖႗႘႙ႠႡႢႣႤႥႦႧႨႩႪႫႬႭႮႯႰႱႲႳႴႵႶႷႸႹႺႻႼႽႾႿჀჁჂჃჄჅაბგდე"
    "ვზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰჱჲჳ྾"
)

_B2048_TAIL = "།༎༏༐༑༆༈༒"

_ECOJI = (
    "🀄🃏🅰🅱🅾🅿🆎🆑🆒🆓🆔🆕🆖🆗🆘🆙🆚🇦🇧🇨🇩🇪🇫🇬🇭🇮🇯🇰🇱🇲🇳🇴"
    "🇵🇶🇷🇸🇹🇺🇻🇼🇽🇾🇿🈁🈂🈚🈯🈲🈳🈴🈵🈶🈷🈸🈹🈺🉐🉑🌀🌁🌂🌃🌄🌅"
    "🌆🌇🌈🌉🌊🌋🌌🌍🌎🌏🌐🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜🌝🌞🌟🌠🌡🌤🌥🌦🌧"
    "🌨🌩🌪🌫🌬🌭🌮🌯🌰🌱🌲🌳🌴🌵🌶🌷🌸🌹🌺🌻🌼🌽🌾🌿🍀🍁🍂🍃🍄🍅🍆🍇"
    "🍈🍉🍊🍋🍌🍍🍎🍏🍐🍑🍒🍓🍔🍕🍖🍗🍘🍙🍚🍛🍜🍝🍞🍟🍠🍡🍢🍣🍤🍥🍦🍧"
    "🍨🍩🍪🍫🍬🍭🍮🍯🍰🍱🍲🍳🍴🍵🍶🍷🍸🍹🍺🍻🍼🍽🍾🍿🎀🎁🎂🎃🎄🎅🎆🎇"
    "🎈🎉🎊🎋🎌🎍🎎🎏🎐🎑🎒🎓🎖🎗🎙🎚🎛🎞🎟🎠🎡🎢🎣🎤🎥🎦🎧🎨🎩🎪🎫🎬"
    "🎭🎮🎯🎰🎱🎲🎳🎴🎵🎶🎷🎸🎹🎺🎻🎼🎽🎾🎿🏀🏁🏂🏃🏄🏅🏆🏇🏈🏉🏊🏋🏌"
    "🏎🏏🏐🏑🏒🏓🏔🏕🏖🏗🏘🏙🏚🏛🏜🏝🏞🏟🏠🏡🏢🏣🏤🏥🏦🏧🏨🏩🏪🏫🏬🏭"
    "🏮🏯🏰🏳🏴🏵🏷🏸🏹🏺🏻🏼🏽🏾🏿🐀🐁🐂🐃🐄🐅🐆🐇🐈🐉🐊🐋🐌🐍🐎🐏🐐"
    "🐑🐒🐓🐔🐕🐖🐗🐘🐙🐚🐛🐜🐝🐞🐟🐠🐡🐢🐣🐤🐥🐦🐧🐨🐩🐪🐫🐬🐭🐮🐯🐰"
    "🐱🐲🐳🐴🐵🐶🐷🐸🐹🐺🐻🐼🐽🐾🐿👀👁👂👃👄👅👆👇👈👉👊👋👌👍👎👏👐"
    "👑👒👓👔👕👖👗👘👙👚👛👜👝👞👟👠👡👢👣👤👥👦👧👨👩👪👫👬👭👮👯👰"
    "👱👲👳👴👵👶👷👸👹👺👻👼👽👾👿💀💁💂💃💄💅💆💇💈💉💊💋💌💍💎💏💐"
    "💑💒💓💔💕💖💗💘💙💚💛💜💝💞💟💠💡💢💣💤💥💦💧💨💩💪💫💬💭💮💯💰"
    "💱💲💳💴💵💶💷💸💹💺💻💼💽💾💿📀📁📂📃📄📅📆📇📈📉📊📋📌📍📎📏📐"
    "📒📓📔📕📖📗📘📙📚📛📜📝📞📟📠📡📢📣📤📥📦📧📨📩📪📫📬📭📮📯📰📱"
    "📲📳📴📵📶📷📸📹📺📻📼📽📿🔀🔁🔂🔃🔄🔅🔆🔇🔈🔉🔊🔋🔌🔍🔎🔏🔐🔑🔒"
    "🔓🔔🔕🔖🔗🔘🔙🔚🔛🔜🔝🔞🔟🔠🔡🔢🔣🔤🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔯🔰🔱🔲"
    "🔳🔴🔵🔶🔷🔸🔹🔺🔻🔼🔽🕉🕊🕋🕌🕍🕎🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞"
    "🕟🕠🕡🕢🕣🕤🕥🕦🕧🕯🕰🕳🕴🕵🕶🕷🕸🕹🕺🖇🖊🖋🖌🖍🖐🖕🖖🖤🖥🖨🖱🖲"
    "🖼🗂🗃🗄🗑🗒🗓🗜🗝🗞🗡🗣🗨🗯🗳🗺🗻🗼🗽🗾🗿😀😁😂😃😄😅😆😇😈😉😊"
    "😋😌😍😎😏😐😑😒😓😔😕😖😗😘😙😚😛😜😝😞😟😠😡😢😣😤😥😦😧😨😩😪"
    "😫😬😭😮😯😰😱😲😳😴😵😶😷😸😹😺😻😼😽😾😿🙀🙁🙂🙃🙄🙅🙆🙇🙈🙉🙊"
    "🙌🙍🙎🙏🚀🚁🚂🚃🚄🚅🚆🚇🚈🚉🚊🚋🚌🚍🚎🚏🚐🚑🚒🚓🚔🚕🚖🚗🚘🚙🚚🚛"
    "🚜🚝🚞🚟🚠🚡🚢🚣🚤🚥🚦🚧🚨🚩🚪🚫🚬🚭🚮🚯🚰🚱🚲🚳🚴🚵🚶🚷🚸🚹🚺🚻"
    "🚼🚽🚾🚿🛀🛁🛂🛃🛄🛅🛋🛌🛍🛎🛏🛐🛑🛒🛠🛡🛢🛣🛤🛥🛩🛫🛬🛰🛳🛴🛵🛶"
    "🛷🛸🛹🤐🤑🤒🤓🤔🤕🤖🤗🤘🤙🤚🤛🤜🤝🤞🤟🤠🤡🤢🤣🤤🤥🤦🤧🤨🤩🤪🤫🤬"
    "🤭🤮🤯🤰🤱🤲🤳🤴🤵🤶🤷🤸🤹🤺🤼🤽🤾🥀🥁🥂🥃🥄🥅🥇🥈🥉🥊🥋🥌🥍🥎🥏"
    "🥐🥑🥒🥓🥔🥕🥖🥗🥘🥙🥚🥛🥜🥝🥞🥟🥠🥡🥢🥣🥤🥥🥦🥧🥨🥩🥪🥫🥬🥭🥮🥯"
    "🥰🥳🥴🥵🥶🥺🥼🥽🥾🥿🦀🦁🦂🦃🦄🦅🦆🦇🦈🦉🦊🦋🦌🦍🦎🦏🦐🦑🦒🦓🦔🦕"
    "🦖🦗🦘🦙🦚🦛🦜🦝🦞🦟🦠🦡🦢🦰🦱🦲🦳🦴🦵🦶🦷🦸🦹🧀🧁🧂🧐🧑🧒🧓🧔🧕"
)

_ECOJI_PAD = "☕"

_ECOJI_PAD4 = "⚜🏍📑🙋"  # the last block's fourth emoji when 4 bytes remain: its two low bits

_B2048 = {char: value for value, char in enumerate(_B2048_BLOCK)}
_B2048_TAILS = {char: value for value, char in enumerate(_B2048_TAIL)}
B2048_ALPHABET = _B2048_BLOCK + _B2048_TAIL
"""Every character a Base2048 run can hold, for ``scan``'s tokenizer."""
_ECOJI_VALUE = {char: value for value, char in enumerate(_ECOJI)}
ECOJI_ALPHABET = _ECOJI + _ECOJI_PAD + _ECOJI_PAD4
"""Every emoji an Ecoji run can hold, for ``scan``'s tokenizer."""


_BYTE = 8
_B2048_BITS = 11
_B2048_TAIL_BITS = 3  # what a tail character carries
_ECOJI_BITS = 10
_ECOJI_PAD4_BITS = 2  # what a four-byte group's last emoji carries
_ECOJI_GROUP = 4  # emoji in a group, padded to it


def _regroup(fields: Iterable[tuple[int, int]], width: int) -> tuple[list[int], int, int]:
    """``(value, bits)`` fields as one bit stream, cut into ``width``-bit values.

    Returns the values and what is left over: its value and its bit count.
    Streamed, so a long run stays linear."""
    mask = (1 << width) - 1
    cut: list[int] = []
    acc = held = 0
    for value, bits in fields:
        acc, held = (acc << bits) | value, held + bits
        while held >= width:
            held -= width
            cut.append((acc >> held) & mask)
            acc &= (1 << held) - 1
    return cut, acc, held


def _octets(raw: bytes) -> Iterator[tuple[int, int]]:
    return ((byte, _BYTE) for byte in raw)


def _b2048_encode(raw: bytes) -> str:
    cut, rest, held = _regroup(_octets(raw), _B2048_BITS)
    chars = [_B2048_BLOCK[value] for value in cut]
    if held:  # the last bits go right-aligned, no padding
        chars.append((_B2048_TAIL if held <= _B2048_TAIL_BITS else _B2048_BLOCK)[rest])
    return "".join(chars)


def decode_base2048(text: str) -> bytes | None:
    """A Base2048 run, back to its bytes, or None unless it re-encodes exactly."""
    if not text:
        return None
    body, last = text[:-1], text[-1]
    values: list[int] = []
    for char in body:
        value = _B2048.get(char)
        if value is None:
            return None
        values.append(value)
    tail = last in _B2048_TAILS
    final = (_B2048_TAILS if tail else _B2048).get(last)
    bits = _B2048_BITS * len(body) + (_B2048_TAIL_BITS if tail else _B2048_BITS)
    last_bits = bits // _BYTE * _BYTE - _B2048_BITS * len(body)
    if final is None or last_bits <= 0:
        return None
    fields = [*((value, _B2048_BITS) for value in values), (final, last_bits)]
    octets, _, held = _regroup(fields, _BYTE)
    decoded = bytes(octets)
    return decoded if not held and _b2048_encode(decoded) == text else None


def _ecoji_encode(raw: bytes) -> str:
    cut, rest, held = _regroup(_octets(raw), _ECOJI_BITS)
    emoji = [_ECOJI[value] for value in cut]
    if held == _ECOJI_PAD4_BITS:
        emoji.append(_ECOJI_PAD4[rest])
    elif held:  # the last bits go left-aligned in one emoji
        emoji.append(_ECOJI[rest << (_ECOJI_BITS - held)])
    emoji += _ECOJI_PAD * (-len(emoji) % _ECOJI_GROUP)
    return "".join(emoji)


def decode_ecoji(text: str) -> bytes | None:
    """An Ecoji run (newlines allowed), back to its bytes, or None unless it
    re-encodes exactly."""
    emoji = text.replace("\n", "")
    fields: list[tuple[int, int]] = []
    for char in emoji:
        if char in _ECOJI_PAD4:
            fields.append((_ECOJI_PAD4.index(char), _ECOJI_PAD4_BITS))
        elif char != _ECOJI_PAD:
            value = _ECOJI_VALUE.get(char)
            if value is None:
                return None
            fields.append((value, _ECOJI_BITS))
    octets, _, _ = _regroup(fields, _BYTE)
    decoded = bytes(octets)
    return decoded if decoded and _ecoji_encode(decoded) == emoji else None


ZALGO_MARKS = "\u0300-\u036f"
"""Combining Diacritical Marks, every mark zalgolib draws from, as a regex range."""
_ZALGO = dict.fromkeys(range(0x300, 0x370))


def decode_zalgo(text: str) -> str:
    """Zalgo text with its marks dropped."""
    return text.translate(_ZALGO)
