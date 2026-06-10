"""
matchers.py
===========
All pattern-matching engines for the Uzbek zxcvbn localization.
Each matcher returns a list of Match objects describing what was found
and the estimated entropy contribution of that match.
"""

from __future__ import annotations
import re
import math
import itertools
from dataclasses import dataclass, field
from typing import Optional

from uzbek_dataset import (
    FULL_DICTIONARY,
    DICTIONARY_RANK,
    LEET_MAP,
    PLAIN_TO_LEET,
    QWERTY_ROWS,
    COMMON_SEQUENCES,
    CURRENT_YEAR,
    MIN_YEAR,
    rank_entropy,
    log2,
)

# ---------------------------------------------------------------------------
# MATCH DATA CLASS
# ---------------------------------------------------------------------------

@dataclass
class Match:
    """Represents a single detected weakness pattern in a password."""
    pattern: str                        # e.g. "dictionary", "leet", "date", "spatial", "context"
    token: str                          # the matched substring
    i: int                              # start index in password
    j: int                              # end index (inclusive)
    entropy: float                      # estimated bits of entropy this match consumes
    # Pattern-specific metadata
    matched_word: Optional[str] = None
    rank: Optional[int] = None
    leet_variations: int = 1
    year: Optional[int] = None
    date_format: Optional[str] = None
    sequence_name: Optional[str] = None
    context_key: Optional[str] = None
    details: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"Match(pattern={self.pattern!r}, token={self.token!r}, "
            f"entropy={self.entropy:.2f}b, matched_word={self.matched_word!r})"
        )

# ---------------------------------------------------------------------------
# 1. DICTIONARY MATCHER
# ---------------------------------------------------------------------------

def _all_substrings(password: str) -> list[tuple[int, int, str]]:
    """Yield (i, j, substring) for all substrings of password."""
    n = len(password)
    for i in range(n):
        for j in range(i + 1, n + 1):
            yield i, j - 1, password[i:j]


def dictionary_matcher(password: str) -> list[Match]:
    """
    Check every substring of `password` against the Uzbek dictionary.
    Returns a Match for each hit.
    """
    matches: list[Match] = []
    pw_lower = password.lower()
    n = len(pw_lower)

    for i in range(n):
        for j in range(i + 1, n + 1):
            token = pw_lower[i:j]
            if token in DICTIONARY_RANK:
                rank = DICTIONARY_RANK[token]
                base_entropy = rank_entropy(rank)
                # Uppercase bonus: if original token has mixed case, attacker
                # must try more variations → add small bonus, but still weak.
                upper_bonus = _uppercase_entropy(password[i:j])
                entropy = base_entropy + upper_bonus
                matches.append(Match(
                    pattern="dictionary",
                    token=password[i:j],
                    i=i, j=j - 1,
                    entropy=entropy,
                    matched_word=token,
                    rank=rank,
                ))
    return _filter_subsumed(matches)


def _uppercase_entropy(token: str) -> float:
    """
    Extra entropy for capitalisation variations.
    Following zxcvbn: log2(#possible_capitalization_combos).
    """
    if token.islower() or token.isupper():
        return 0.0
    uppers = sum(1 for c in token if c.isupper())
    lowers = sum(1 for c in token if c.islower())
    combos = sum(
        math.comb(uppers + lowers, i)
        for i in range(1, min(uppers, lowers) + 1)
    )
    return log2(max(combos, 1))


# ---------------------------------------------------------------------------
# 2. LEETSPEAK / SUBSTITUTION MATCHER
# ---------------------------------------------------------------------------

def _deobfuscate(token: str) -> list[str]:
    """
    Generate all plain-text candidates by reversing leet substitutions.
    Returns a list of possible original words.
    """
    candidates: set[str] = set()

    def _expand(chars: list[str], idx: int, current: list[str]) -> None:
        if idx == len(chars):
            candidates.add("".join(current))
            return
        c = chars[idx].lower()
        # Try the character as-is
        _expand(chars, idx + 1, current + [c])
        # Try all plain-text substitutions
        if c in LEET_MAP:
            for plain in LEET_MAP[c]:
                _expand(chars, idx + 1, current + [plain])

    _expand(list(token), 0, [])
    return list(candidates)


def _count_leet_subs(token: str) -> int:
    """Count how many characters in token are leet substitutions."""
    return sum(1 for c in token.lower() if c in LEET_MAP)


def leet_matcher(password: str) -> list[Match]:
    """
    Detect leet-speak obfuscation: e.g., `S@man4dar` → `samandar`.
    For each substring, deobfuscate and check against dictionary.
    Also handles mixed-case tokens by lowercasing before matching.
    """
    matches: list[Match] = []
    pw = password
    n = len(pw)

    for i in range(n):
        for j in range(i + 2, n + 1):  # min length 3 to be meaningful
            token = pw[i:j]
            token_lower = token.lower()

            has_leet = any(c in LEET_MAP for c in token_lower)
            if not has_leet:
                continue  # no leet chars → skip

            candidates = _deobfuscate(token)
            for candidate in candidates:
                # Must match dictionary AND differ from the raw lowercased token
                if candidate in DICTIONARY_RANK and candidate != token_lower:
                    rank = DICTIONARY_RANK[candidate]
                    leet_count = _count_leet_subs(token)
                    # Guard: if leet_count is 0 somehow, still score as dictionary
                    if leet_count == 0:
                        leet_count = 1
                    leet_entropy = rank_entropy(rank) + log2(2 ** leet_count)
                    matches.append(Match(
                        pattern="leet",
                        token=token,
                        i=i, j=j - 1,
                        entropy=leet_entropy,
                        matched_word=candidate,
                        rank=rank,
                        leet_variations=2 ** leet_count,
                        details={"leet_chars_count": leet_count},
                    ))

    return _filter_subsumed(matches)


# ---------------------------------------------------------------------------
# 3. DATE & YEAR MATCHER
# ---------------------------------------------------------------------------

# Year pattern: standalone 4-digit or 2-digit year
_YEAR_4_RE = re.compile(r"(?<!\d)(19[5-9]\d|20[0-2]\d)(?!\d)")
_YEAR_2_RE = re.compile(r"(?<!\d)([5-9]\d|0[0-9]|1[0-9]|2[0-6])(?!\d)")

# Common date formats
_DATE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("DDMMYYYY", re.compile(r"(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])(19[5-9]\d|20[0-2]\d)")),
    ("MMDDYYYY", re.compile(r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(19[5-9]\d|20[0-2]\d)")),
    ("DDMMYY",   re.compile(r"(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])([5-9]\d|0\d|1\d|2[0-6])")),
    ("YYYYMMDD", re.compile(r"(19[5-9]\d|20[0-2]\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])")),
]

def _year_entropy(year: int) -> float:
    """Entropy of guessing a year in [MIN_YEAR, CURRENT_YEAR]."""
    span = CURRENT_YEAR - MIN_YEAR + 1  # ~77 values
    return log2(span)  # ≈ 6.3 bits — very low


def date_matcher(password: str) -> list[Match]:
    """
    Detect years (4-digit and 2-digit) and common date formats
    embedded in passwords.
    """
    matches: list[Match] = []
    pw = password

    # 4-digit years
    for m in _YEAR_4_RE.finditer(pw):
        year = int(m.group(1))
        matches.append(Match(
            pattern="date",
            token=m.group(),
            i=m.start(), j=m.end() - 1,
            entropy=_year_entropy(year),
            year=year,
            date_format="YYYY",
        ))

    # 2-digit years (50-99 = 1950-1999, 00-26 = 2000-2026)
    for m in _YEAR_2_RE.finditer(pw):
        suffix = int(m.group(1))
        year = (1900 + suffix) if suffix >= 50 else (2000 + suffix)
        # Only 2-digit: log2(77) but with slightly less certainty about century
        matches.append(Match(
            pattern="date",
            token=m.group(),
            i=m.start(), j=m.end() - 1,
            entropy=_year_entropy(year) + 1.0,  # +1 bit for century ambiguity
            year=year,
            date_format="YY",
        ))

    # Full date formats
    for fmt_name, pattern in _DATE_PATTERNS:
        for m in pattern.finditer(pw):
            # Full date: day(31) * month(12) * years(77) combos
            full_date_entropy = log2(31 * 12 * (CURRENT_YEAR - MIN_YEAR + 1))
            matches.append(Match(
                pattern="date",
                token=m.group(),
                i=m.start(), j=m.end() - 1,
                entropy=full_date_entropy,
                date_format=fmt_name,
            ))

    return _filter_subsumed(matches)


# ---------------------------------------------------------------------------
# 4. SPATIAL / KEYBOARD PATTERN MATCHER
# ---------------------------------------------------------------------------

def _build_adjacency_map() -> dict[str, set[str]]:
    """Build a character → adjacent characters map from QWERTY rows."""
    adj: dict[str, set[str]] = {}
    for row in QWERTY_ROWS:
        for idx, char in enumerate(row):
            neighbors: set[str] = set()
            if idx > 0:
                neighbors.add(row[idx - 1])
            if idx < len(row) - 1:
                neighbors.add(row[idx + 1])
            adj.setdefault(char, set()).update(neighbors)
    return adj

ADJACENCY_MAP = _build_adjacency_map()


def _is_spatial_sequence(token: str, min_len: int = 3) -> bool:
    """Return True if `token` forms a keyboard walk of at least `min_len` chars."""
    if len(token) < min_len:
        return False
    t = token.lower()
    for i in range(len(t) - 1):
        if t[i + 1] not in ADJACENCY_MAP.get(t[i], set()):
            return False
    return True


def spatial_matcher(password: str) -> list[Match]:
    """
    Detect keyboard spatial patterns (walks) in the password.
    Also checks against COMMON_SEQUENCES list.
    """
    matches: list[Match] = []
    pw = password
    n = len(pw)

    # Check for common pre-defined sequences
    pw_lower = pw.lower()
    for seq in COMMON_SEQUENCES:
        start = pw_lower.find(seq)
        if start != -1:
            # Entropy = log2(keyboard_size * avg_branching_factor ^ len)
            # Conservative estimate: 2 directions * 10 rows * branching ~2
            entropy = log2(len(seq)) + log2(2)  # very low
            matches.append(Match(
                pattern="spatial",
                token=pw[start:start + len(seq)],
                i=start, j=start + len(seq) - 1,
                entropy=entropy,
                sequence_name="common_sequence",
                details={"sequence": seq},
            ))

    # Detect keyboard walks dynamically
    i = 0
    while i < n - 2:
        j = i + 1
        while j < n and pw[j].lower() in ADJACENCY_MAP.get(pw[j - 1].lower(), set()):
            j += 1
        if j - i >= 3:
            token = pw[i:j]
            # Entropy formula: log2(starting_keys) + (length-1)*log2(avg_adjacent)
            avg_adjacent = 2.0
            entropy = log2(len(ADJACENCY_MAP)) + (len(token) - 1) * log2(avg_adjacent)
            matches.append(Match(
                pattern="spatial",
                token=token,
                i=i, j=j - 1,
                entropy=entropy,
                sequence_name="keyboard_walk",
            ))
            i = j
        else:
            i += 1

    return _filter_subsumed(matches)


# ---------------------------------------------------------------------------
# 5. CONTEXTUAL MATCHER (personal data)
# ---------------------------------------------------------------------------

def contextual_matcher(password: str, user_context: dict[str, str]) -> list[Match]:
    """
    Check if the password contains user's personal data:
    name, surname, birth year, city, etc.
    Handles partial matches, reversed strings, and short abbreviations.
    """
    matches: list[Match] = []
    pw_lower = password.lower()

    context_tokens: list[tuple[str, str]] = []  # (token, context_key)

    for key, value in user_context.items():
        if not value or len(value) < 2:
            continue
        v = value.lower().strip()
        context_tokens.append((v, key))
        # Also add common mutations:
        context_tokens.append((v[::-1], f"{key}_reversed"))          # reversed
        if len(v) >= 3:
            context_tokens.append((v[:3], f"{key}_prefix3"))         # first 3 chars
        if "_" in v:
            context_tokens.append((v.replace("_", ""), key))         # no separator

    for token_val, ctx_key in context_tokens:
        if len(token_val) < 2:
            continue
        pos = pw_lower.find(token_val)
        if pos != -1:
            # Personal data is the weakest possible → entropy ≈ 0 + small variation
            entropy = log2(max(len(token_val), 1)) * 0.5  # extremely low
            matches.append(Match(
                pattern="context",
                token=password[pos:pos + len(token_val)],
                i=pos, j=pos + len(token_val) - 1,
                entropy=entropy,
                context_key=ctx_key,
                details={"context_value": token_val, "context_type": ctx_key},
            ))

    return _filter_subsumed(matches)


# ---------------------------------------------------------------------------
# UTILITY: Filter subsumed matches (keep longest/best match)
# ---------------------------------------------------------------------------

def _filter_subsumed(matches: list[Match]) -> list[Match]:
    """
    Remove matches that are fully contained within a longer match
    with equal or lower entropy (keep the most significant ones).
    """
    if len(matches) <= 1:
        return matches

    # Sort by length descending, then entropy ascending
    sorted_m = sorted(matches, key=lambda m: (-(m.j - m.i), m.entropy))
    kept: list[Match] = []
    covered: set[int] = set()

    for m in sorted_m:
        span = set(range(m.i, m.j + 1))
        if span & covered:
            # Some overlap — only skip if fully subsumed
            if span <= covered:
                continue
        kept.append(m)
        covered.update(span)

    return sorted(kept, key=lambda m: m.i)
