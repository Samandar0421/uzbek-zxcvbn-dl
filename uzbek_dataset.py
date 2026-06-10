"""
uzbek_dataset.py
================
Hyper-localized dataset for Uzbek password strength analysis.
Contains: names, common words, brands, sports teams, regions,
          leetspeak substitution map, keyboard spatial patterns.
"""

from __future__ import annotations
import math

# ---------------------------------------------------------------------------
# 1. LEETSPEAK SUBSTITUTION MAP (bidirectional)
# ---------------------------------------------------------------------------
# Key = leet char   Value = list of plain chars it can represent
LEET_MAP: dict[str, list[str]] = {
    "@": ["a", "o"],
    "4": ["a"],
    "3": ["e"],
    "1": ["i", "l"],
    "!": ["i", "l"],
    "0": ["o"],
    "5": ["s"],
    "$": ["s"],
    "7": ["t"],
    "+": ["t"],
    "6": ["g", "b"],
    "8": ["b"],
    "9": ["g"],
    "|": ["i", "l"],
    "2": ["z"],
    "q": ["q", "k"],   # Uzbek-specific: "qu" -> "k" sound
}

# Reverse map: plain char -> list of possible leet substitutions
PLAIN_TO_LEET: dict[str, list[str]] = {}
for leet_char, plain_chars in LEET_MAP.items():
    for p in plain_chars:
        PLAIN_TO_LEET.setdefault(p, []).append(leet_char)

# ---------------------------------------------------------------------------
# 2. UZBEK NAMES (common first names — male & female)
# ---------------------------------------------------------------------------
UZBEK_MALE_NAMES: list[str] = [
    # Classic & most common
    "ali", "alijon", "alisher", "alixon", "jasur", "jamshid", "javlon",
    "sardor", "samandar", "sanjar", "sherzod", "shohruh", "shodmon",
    "bobur", "botir", "behruz", "bekzod", "bahodir", "baxtiyor",
    "dilshod", "doniyor", "davron", "dostonbek",
    "eldor", "elmurod", "elbek", "elyor",
    "farrux", "firdavs", "furqat",
    "humoyun", "husan", "husayn", "hamza", "hamid",
    "ilhom", "ibrohim", "ismoil",
    "jahongir", "javokhir",
    "kamol", "komil", "komiljon",
    "lochinbek", "laziz", "lazzat",
    "mansur", "murod", "muhammadali", "muazzam", "mirzo",
    "nodir", "nodirjon", "nozim",
    "obid", "oybek",
    "parviz",
    "qodir", "qodirbek",
    "ravshan", "rustam", "rauf",
    "salim", "sanjar", "sarvarbek", "saidakbar", "sohibjon", "soliyev",
    "temur", "tohir", "tolib",
    "ulugbek", "umid",
    "vohid", "valijon",
    "xurshid", "xasan", "xusayn",
    "yorqin", "yusuf",
    "zafar", "zubaydullo", "ziyod",
]

UZBEK_FEMALE_NAMES: list[str] = [
    "aziza", "adolat", "anora",
    "barno", "binafsha",
    "dilfuza", "dilnoza", "dildora",
    "feruza", "fotima",
    "gulnora", "gulbahor", "gulnoz",
    "hilola", "hulkar",
    "iroda",
    "kumush", "kamola",
    "lobar", "lola",
    "malika", "maftuna", "muazzam", "munira", "mohira", "mohinur",
    "nafisa", "nodira", "nilufar",
    "oydin", "oysha",
    "parizod",
    "rano", "rohila",
    "sarvinoz", "saodat", "shahnoza", "shahlo", "sitora", "sevinch",
    "tabassum",
    "umida",
    "vasila",
    "xurmo", "xilola",
    "yulduz",
    "zulfiya", "ziyoda", "zuhra",
]

UZBEK_SURNAMES: list[str] = [
    "abdullayev", "ahmedov", "akbarov", "alijonov", "alimov",
    "botirov", "burxonov",
    "choriyev",
    "eshmatov",
    "fayzullayev",
    "hasanov", "holiqov", "holmatov",
    "ismoilov",
    "jurayev",
    "karimov", "kalandarov",
    "mahmudov", "mirzayev", "musayev",
    "nazarov", "normatov",
    "ortiqov",
    "qodirov", "qosimov",
    "rahimov", "rasulов", "razzaqov",
    "salimov", "sobirov", "soliyev", "sultonov",
    "toshmatov", "tursunov",
    "umarov", "usmonov",
    "xoliqov", "xolmatov",
    "yusupov",
    "zaripov",
]

# ---------------------------------------------------------------------------
# 3. COMMON UZBEK WORDS (everyday vocabulary likely used in passwords)
# ---------------------------------------------------------------------------
COMMON_UZBEK_WORDS: list[str] = [
    # Greetings / phrases
    "salom", "assalomu", "alaykum", "rahmat", "xayr",
    # Family
    "oila", "ona", "ota", "aka", "uka", "opa", "singil", "bola", "farzand",
    # Nature / places
    "daryo", "tog", "quyosh", "oy", "yulduz", "shamol", "bahor", "yoz", "kuz", "qish",
    # Emotions / traits
    "sevgi", "muhabbat", "xursand", "baxtli", "quvonch", "hayot", "umid",
    # Numbers (written out)
    "bir", "ikki", "uch", "tort", "besh", "olti", "yetti", "sakkiz", "toqqiz", "on",
    # Days / months
    "dushanba", "seshanba", "chorshanba", "payshanba", "juma", "shanba", "yakshanba",
    "yanvar", "fevral", "mart", "aprel", "may", "iyun",
    "iyul", "avgust", "sentabr", "oktabr", "noyabr", "dekabr",
    # Common password stems
    "parol", "login", "kalit", "kirish", "chiqish",
    # Religion / culture
    "bismillah", "alloh", "xudo", "namoz", "ramazon",
    # Tech / brands
    "telefon", "internet", "kompyuter",
]

# ---------------------------------------------------------------------------
# 4. UZBEKISTAN-SPECIFIC BRANDS, SPORTS TEAMS & CULTURAL REFERENCES
# ---------------------------------------------------------------------------
UZ_BRANDS_AND_TEAMS: list[str] = [
    # Telecom
    "ucell", "beeline", "uzmobile", "mobiuz",
    # Banks
    "agrobank", "kapitalbank", "hamkorbank", "ipoteka", "xalqbank",
    # Sports
    "pakhtakor", "nasaf", "bunyodkor", "locomotiv", "neftchi",
    "lokomotiv",
    # Cities as teams / common refs
    "toshkent", "samarkand", "buxoro", "namangan", "andijon",
    "fargona", "qashqadaryo", "surxondaryo", "xorazm", "navoiy",
    "jizzax", "sirdaryo",
    # National symbols
    "uzbekistan", "ozbekiston", "milliy", "mustaqillik",
    # Food / culture
    "palov", "somsa", "lagmon", "choyxona", "bozor",
]

# ---------------------------------------------------------------------------
# 5. KEYBOARD SPATIAL PATTERNS
# ---------------------------------------------------------------------------
# Standard QWERTY rows
QWERTY_ROWS: list[str] = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Common sequences derived from Uzbek keyboard (Latin layout - same as QWERTY)
# Also includes Cyrillic-influence sequences common in UZ
COMMON_SEQUENCES: list[str] = [
    # QWERTY walks
    "qwerty", "qwert", "werty", "asdfg", "sdfgh", "zxcvb",
    "12345", "123456", "1234567", "12345678", "123456789",
    "09876", "098765",
    # Number patterns
    "111111", "222222", "112233", "121212",
    # Common UZ keyboard combos
    "qweasd", "rewqaz",
    # UZ phone number starts (common as passwords)
    "998", "9989", "99890", "99893", "99894", "99897", "99899",
    # Uzbek-specific PIN-like patterns
    "1111", "0000", "1234", "4321", "0101", "3131",
]

# ---------------------------------------------------------------------------
# 6. FULL MERGED DICTIONARY (lowercase)
# ---------------------------------------------------------------------------
def build_full_dictionary() -> list[str]:
    """
    Merge all word lists into a single deduplicated sorted list.
    Used as the primary corpus for dictionary matching.
    """
    raw = (
        UZBEK_MALE_NAMES
        + UZBEK_FEMALE_NAMES
        + UZBEK_SURNAMES
        + COMMON_UZBEK_WORDS
        + UZ_BRANDS_AND_TEAMS
        + COMMON_SEQUENCES
    )
    seen: set[str] = set()
    result: list[str] = []
    for word in raw:
        w = word.lower().strip()
        if w and w not in seen:
            seen.add(w)
            result.append(w)
    return sorted(result)

FULL_DICTIONARY: list[str] = build_full_dictionary()

# Dictionary rank map: word -> rank (1 = most dangerous)
DICTIONARY_RANK: dict[str, int] = {
    word: rank + 1 for rank, word in enumerate(FULL_DICTIONARY)
}

# ---------------------------------------------------------------------------
# 7. ENTROPY HELPERS
# ---------------------------------------------------------------------------
CURRENT_YEAR: int = 2026
MIN_YEAR: int = 1950

def log2(x: float) -> float:
    """Safe log2."""
    return math.log2(x) if x > 0 else 0.0

def corpus_entropy(corpus_size: int) -> float:
    """
    Base entropy for a dictionary attack against a corpus of N words.
    H = log2(N)
    """
    return log2(corpus_size)

def rank_entropy(rank: int) -> float:
    """
    Entropy based on word rank: log2(rank).
    Lower rank = more common = lower entropy = weaker.
    """
    return log2(rank)

DICT_CORPUS_ENTROPY: float = corpus_entropy(len(FULL_DICTIONARY))
