"""
feedback.py
===========
Human-readable Uzbek-language feedback generator and
secure password recommendation engine.
"""

from __future__ import annotations
import random
import string
import secrets
import math
from typing import Optional

from matchers import Match
from scorer import PasswordResult, SCORE_LABELS

# ---------------------------------------------------------------------------
# FEEDBACK TEMPLATES (Uzbek)
# ---------------------------------------------------------------------------

# Pattern-specific warning messages
PATTERN_WARNINGS: dict[str, list[str]] = {
    "dictionary": [
        "'{word}' — o'zbek tilidagi keng tarqalgan so'z yoki ism. "
        "Lug'at hujumi orqali bir necha soniyada topilishi mumkin!",

        "'{word}' so'zi o'zbek parol lug'atlarida mavjud. "
        "Xaker dasturlari bu so'zni birinchi navbatda sinab ko'radi.",

        "Bu parol o'zbek ism yoki so'ziga asoslangan. "
        "Brute-force hujumlari uchun maqsadli obyekt bo'lishi mumkin.",
    ],
    "leet": [
        "'{token}' → '{word}': Harflarni belgilar bilan almashtirish "
        "(masalan, 'a'→'@', 's'→'5') zamonaviy xaker dasturlariga to'siq bo'lmaydi. "
        "Bu usul 1990-yillarda mashhur edi, hozir keng ma'lum.",

        "Leet-speak ('{token}') hujumchilarga to'siq yaratmaydi — "
        "zamonaviy cracker dasturlari barcha almashtirishlarni avtomatik sinab ko'radi.",
    ],
    "date": [
        "Parolda {year}-yil aniqlandi. Tug'ilgan yil yoki muhim sana — "
        "ijtimoiy muhandislik hujumlari uchun birinchi sinov ob'ekti.",

        "{year} — faqat {span} yillik oraliqdan biri. "
        "Sana qo'shilgan parollar juda bashorat qilinadigan bo'ladi.",
    ],
    "spatial": [
        "Klaviatura bo'ylab ketma-ket bosish ('{token}') — "
        "eng keng tarqalgan parol odatlaridan biri. "
        "Cracker dasturlari bunday naqshlarni bir zumda topadi.",

        "'{token}' — klaviatura yo'li naqshi. "
        "Barcha klaviatura ketma-ketliklari hujum lug'atlarida mavjud.",
    ],
    "context": [
        "Parolda shaxsiy ma'lumot ({ctx_key}) aniqlandi! "
        "Ijtimoiy muhandislik hujumlari shaxsiy ma'lumotlardan foydalanadi. "
        "Bu parol siz haqingizda ma'lumot bilgan har kimga ochiq!",

        "Shaxsiy ma'lumotingiz parolda ishlatilgan ({ctx_key}). "
        "Facebook, Instagram yoki LinkedIn orqali bu ma'lumot osongina topiladi.",
    ],
}

GENERAL_SUGGESTIONS: list[str] = [
    "Kamida 12 ta belgidan iborat parol ishlating.",
    "Katta va kichik harflar, raqamlar va maxsus belgilarni aralashtiring.",
    "Parolda shaxsiy ma'lumot (ism, tug'ilgan yil, telefon) ishlatmang.",
    "Har bir hisob uchun alohida, noyob parol o'rnating.",
    "Parol menejeri (Bitwarden, KeePass) ishlatishni o'ylab ko'ring.",
    "Lug'atda mavjud so'zlarni to'g'ridan-to'g'ri ishlatmang.",
]

# ---------------------------------------------------------------------------
# FEEDBACK GENERATOR
# ---------------------------------------------------------------------------

def _format_warning(match: Match) -> Optional[str]:
    """Generate a specific Uzbek warning for a match."""
    templates = PATTERN_WARNINGS.get(match.pattern, [])
    if not templates:
        return None

    template = random.choice(templates)
    year_span = 2026 - 1950 + 1

    try:
        msg = template.format(
            word=match.matched_word or match.token,
            token=match.token,
            year=match.year or "",
            span=year_span,
            ctx_key=_translate_context_key(match.context_key or ""),
        )
    except KeyError:
        msg = template
    return msg


def _translate_context_key(key: str) -> str:
    """Translate context key names to Uzbek."""
    translations = {
        "first_name":       "ism",
        "last_name":        "familiya",
        "birth_year":       "tug'ilgan yil",
        "city":             "shahar",
        "phone":            "telefon raqami",
        "first_name_reversed":  "teskari ism",
        "last_name_reversed":   "teskari familiya",
        "first_name_prefix3":   "ismning bosh harflari",
    }
    for k, v in translations.items():
        if k in key:
            return v
    return key


def generate_feedback(result: PasswordResult) -> dict:
    """
    Analyse the match list and produce structured Uzbek feedback.
    Returns dict with 'warnings', 'suggestions', 'score_label', 'crack_times'.
    """
    warnings: list[str] = []
    seen_patterns: set[str] = set()

    for match in result.optimal_matches:
        if match.pattern == "bruteforce":
            continue
        # Avoid duplicate pattern warnings
        dedup_key = f"{match.pattern}:{match.matched_word or match.token[:6]}"
        if dedup_key in seen_patterns:
            continue
        seen_patterns.add(dedup_key)

        warning = _format_warning(match)
        if warning:
            warnings.append(warning)

    # Global warnings by score
    score = result.score
    if score == 0:
        warnings.insert(0,
            "⚠️  Bu parol JUDA ZAIF! Uni hoziroq o'zgartiring.")
    elif score == 1:
        warnings.insert(0,
            "⚠️  Bu parol ZAIF. Tajovuzkorlar uni tez buzishi mumkin.")
    elif score == 2:
        warnings.insert(0,
            "ℹ️  Bu parol O'RTACHA. Yaxshilash tavsiya etiladi.")

    suggestions = list(GENERAL_SUGGESTIONS[:3])

    result.warnings = warnings
    result.suggestions = suggestions

    return {
        "score": score,
        "score_label": SCORE_LABELS[score],
        "entropy_bits": round(result.entropy, 2),
        "warnings": warnings,
        "suggestions": suggestions,
        "crack_times": result.crack_time_estimates,
        "detected_patterns": [
            {
                "pattern": m.pattern,
                "token": m.token,
                "entropy": round(m.entropy, 2),
                "detail": m.matched_word or m.context_key or m.sequence_name or "",
            }
            for m in result.optimal_matches
            if m.pattern != "bruteforce"
        ],
    }


# ---------------------------------------------------------------------------
# SECURE PASSWORD RECOMMENDATION ENGINE
# ---------------------------------------------------------------------------

# High-entropy word components (NOT in the Uzbek dictionary)
_STRONG_WORDS: list[str] = [
    "Arxiv", "Velosiped", "Barqaror", "Doimiy", "Foydali",
    "Gajak", "Hamisha", "Istiqlol", "Jadval", "Kerakli",
    "Lozim", "Mavsum", "Noyob", "Oyoq", "Pishiq",
    "Qattiq", "Ravshan", "Sokin", "Tezkor", "Uchqur",
]

_SPECIAL_CHARS: list[str] = ["!", "@", "#", "$", "%", "&", "*", "?", "~", "^"]
_SEPARATORS: list[str] = ["-", "_", ".", "+", "="]


def _random_strong_component(length: int = 4) -> str:
    """Generate a short random alphanumeric string (high entropy filler)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _mangle_context(value: str) -> str:
    """
    Take a personal word and make it unrecognizable while keeping
    it slightly memorable — add random case flips and insert a digit.
    """
    if not value or len(value) < 2:
        return value
    v = list(value.lower())
    # Flip case of 2 random positions
    positions = random.sample(range(len(v)), min(2, len(v)))
    for p in positions:
        if v[p].isalpha():
            v[p] = v[p].upper()
    # Insert a random digit in the middle
    mid = len(v) // 2
    v.insert(mid, str(secrets.randbelow(10)))
    return "".join(v)


def recommend_passwords(
    user_context: dict[str, str],
    count: int = 3,
) -> list[dict[str, str]]:
    """
    Generate `count` secure, memorable password alternatives.
    Strategy:
      1. Passphrase-style: 3 unrelated strong words + special + digits
      2. Mangled context: user's context word, heavily modified + random entropy
      3. Fully random but pronounceable
    """
    recommendations: list[dict[str, str]] = []

    # --- Strategy 1: Passphrase (most secure & memorable) ---
    words = random.sample(_STRONG_WORDS, 3)
    sep = secrets.choice(_SEPARATORS)
    suffix = _random_strong_component(3) + secrets.choice(_SPECIAL_CHARS)
    passphrase = sep.join(words) + sep + suffix
    recommendations.append({
        "password": passphrase,
        "strategy": "Passphrase (3 ta kuchli so'z + tasodifiy belgilar)",
        "why_strong": (
            "Uch ta bog'liq bo'lmagan so'z kombinatsiyasi — "
            "lug'at hujumlariga qarshi juda kuchli. "
            "Eslab qolish oson, buzish qiyin."
        ),
    })

    # --- Strategy 2: Mangled personal context ---
    # Pick one piece of context, mangle it beyond recognition, add entropy
    context_vals = [v for v in user_context.values() if v and len(v) >= 3]
    if context_vals:
        base = random.choice(context_vals)
    else:
        base = random.choice(_STRONG_WORDS)

    mangled = _mangle_context(base)
    filler = _random_strong_component(5)
    special = secrets.choice(_SPECIAL_CHARS) + secrets.choice(_SPECIAL_CHARS)
    strategy2 = mangled + special + filler
    recommendations.append({
        "password": strategy2,
        "strategy": "Shaxsiy asosga ega, yuqori entropiyali",
        "why_strong": (
            "Sizning kontekstingizdan olingan va to'liq o'zgartirilgan. "
            "Eslab qolish mumkin, lekin brute-force'ga chidamli. "
            "Qo'shimcha tasodifiy belgilar uni juda kuchli qiladi."
        ),
    })

    # --- Strategy 3: Fully cryptographic random ---
    alphabet = string.ascii_letters + string.digits + "!@#$%&*?"
    rand_pw = "".join(secrets.choice(alphabet) for _ in range(16))
    recommendations.append({
        "password": rand_pw,
        "strategy": "To'liq kriptografik tasodifiy (eng kuchli)",
        "why_strong": (
            "Hech qanday naqsh yo'q — to'liq tasodifiy. "
            "Parol menejerida saqlang (Bitwarden, KeePass). "
            "Hozirgi kompyuterlar buni millionlab yillarda ham buz olmaydi."
        ),
    })

    return recommendations
