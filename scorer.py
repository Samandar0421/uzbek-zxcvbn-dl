"""
scorer.py
=========
Entropy-based password strength scorer for the Uzbek zxcvbn system.

Scoring methodology (adapted from Dropbox's zxcvbn paper):
  1. Decompose password into non-overlapping matches using dynamic programming.
  2. The score for a password = entropy of its optimal (lowest-entropy) decomposition.
  3. Unmatched characters contribute brute-force entropy.
  4. Final score maps to 5 levels: 0 (very weak) → 4 (very strong).
"""

from __future__ import annotations
import math
import string
import re
from dataclasses import dataclass
from typing import Optional

from matchers import Match, log2

# ---------------------------------------------------------------------------
# BRUTE-FORCE CHARSET SIZE ESTIMATOR
# ---------------------------------------------------------------------------

def _bruteforce_charset_size(password: str) -> int:
    """
    Estimate the character set size for brute-force entropy calculation.
    Based on which character classes are present in the password.
    """
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    # Common symbols
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        size += 33
    # Uzbek-specific / extended chars (if any)
    if re.search(r"[^\x00-\x7F]", password):
        size += 64  # rough estimate for non-ASCII
    return max(size, 1)


def bruteforce_entropy(length: int, charset_size: int) -> float:
    """H = length * log2(charset_size)"""
    return length * log2(charset_size)


# ---------------------------------------------------------------------------
# DYNAMIC PROGRAMMING: OPTIMAL MATCH SEQUENCE
# ---------------------------------------------------------------------------

def _minimum_entropy_match_sequence(
    password: str,
    matches: list[Match],
) -> list[Match]:
    """
    DP to find the minimum-entropy decomposition of the password.
    Any gap between matches is filled with brute-force entropy.

    Returns the optimal list of matches covering the full password.
    """
    n = len(password)
    charset_size = _bruteforce_charset_size(password)

    # up[i] = minimum entropy to cover password[0..i-1]
    up: list[float] = [0.0] * (n + 1)
    backpointer: list[Optional[Match]] = [None] * (n + 1)

    for k in range(1, n + 1):
        # Brute-force this single character
        up[k] = up[k - 1] + log2(charset_size)

        for m in matches:
            if m.j + 1 != k:
                continue
            # Cost to include this match
            candidate = up[m.i] + m.entropy
            if candidate < up[k]:
                up[k] = candidate
                backpointer[k] = m

    # Reconstruct optimal sequence
    optimal: list[Match] = []
    k = n
    while k > 0:
        m = backpointer[k]
        if m is not None:
            optimal.append(m)
            k = m.i
        else:
            # Single brute-force character at position k-1
            bf_match = Match(
                pattern="bruteforce",
                token=password[k - 1],
                i=k - 1, j=k - 1,
                entropy=log2(charset_size),
            )
            optimal.append(bf_match)
            k -= 1

    optimal.reverse()
    return optimal


# ---------------------------------------------------------------------------
# ENTROPY → SCORE MAPPING
# ---------------------------------------------------------------------------

# Thresholds in bits (calibrated for Uzbek context):
# Very Weak  < 25 bits  → Score 0
# Weak       < 40 bits  → Score 1
# Fair       < 55 bits  → Score 2
# Strong     < 70 bits  → Score 3
# Very Strong >= 70 bits → Score 4

ENTROPY_THRESHOLDS: list[float] = [25.0, 40.0, 55.0, 70.0]

SCORE_LABELS: dict[int, dict[str, str]] = {
    0: {
        "en": "Very Weak",
        "uz": "Juda zaif",
        "color": "🔴",
    },
    1: {
        "en": "Weak",
        "uz": "Zaif",
        "color": "🟠",
    },
    2: {
        "en": "Fair",
        "uz": "O'rtacha",
        "color": "🟡",
    },
    3: {
        "en": "Strong",
        "uz": "Kuchli",
        "color": "🟢",
    },
    4: {
        "en": "Very Strong",
        "uz": "Juda kuchli",
        "color": "✅",
    },
}


def entropy_to_score(entropy: float) -> int:
    for score, threshold in enumerate(ENTROPY_THRESHOLDS):
        if entropy < threshold:
            return score
    return 4


# ---------------------------------------------------------------------------
# CRACK TIME ESTIMATOR
# ---------------------------------------------------------------------------

# Assumptions (conservative estimates for 2024 hardware):
ONLINE_THROTTLED_RATE   = 100          # guesses/second  (rate-limited login)
ONLINE_UNTHROTTLED_RATE = 10_000       # guesses/second  (no rate limit)
OFFLINE_SLOW_RATE       = 1_000_000    # guesses/second  (bcrypt)
OFFLINE_FAST_RATE       = 100_000_000_000  # guesses/second  (MD5/SHA1 GPU)


def _seconds_to_human(seconds: float) -> str:
    if seconds < 1:
        return "bir soniyadan kam"
    if seconds < 60:
        return f"{seconds:.0f} soniya"
    if seconds < 3600:
        return f"{seconds / 60:.0f} daqiqa"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} soat"
    if seconds < 86400 * 30:
        return f"{seconds / 86400:.0f} kun"
    if seconds < 86400 * 365:
        return f"{seconds / (86400 * 30):.0f} oy"
    if seconds < 86400 * 365 * 100:
        return f"{seconds / (86400 * 365):.0f} yil"
    return "asrlar"


def crack_times(entropy: float) -> dict[str, str]:
    """Return estimated crack times for various attack scenarios."""
    guesses = 2 ** entropy
    return {
        "online_throttled":    _seconds_to_human(guesses / ONLINE_THROTTLED_RATE),
        "online_unthrottled":  _seconds_to_human(guesses / ONLINE_UNTHROTTLED_RATE),
        "offline_slow_bcrypt": _seconds_to_human(guesses / OFFLINE_SLOW_RATE),
        "offline_fast_gpu":    _seconds_to_human(guesses / OFFLINE_FAST_RATE),
    }


# ---------------------------------------------------------------------------
# MAIN SCORING FUNCTION
# ---------------------------------------------------------------------------

@dataclass
class PasswordResult:
    password: str
    score: int
    entropy: float
    crack_time_estimates: dict[str, str]
    optimal_matches: list[Match]
    all_matches: list[Match]
    warnings: list[str]
    suggestions: list[str]

    def label(self) -> dict[str, str]:
        return SCORE_LABELS[self.score]


def score_password(
    password: str,
    all_matches: list[Match],
) -> PasswordResult:
    """
    Given a password and all detected matches, compute the final
    strength score using the minimum-entropy DP approach.
    """
    if not password:
        return PasswordResult(
            password="",
            score=0,
            entropy=0.0,
            crack_time_estimates=crack_times(0),
            optimal_matches=[],
            all_matches=[],
            warnings=["Parol bo'sh!"],
            suggestions=["Parol kiriting."],
        )

    optimal = _minimum_entropy_match_sequence(password, all_matches)
    total_entropy = sum(m.entropy for m in optimal)

    # Minimum floor: brute-force of the whole password
    charset_size = _bruteforce_charset_size(password)
    bf_entropy = bruteforce_entropy(len(password), charset_size)
    # Use whichever is LOWER (more pessimistic for attacker advantage)
    final_entropy = min(total_entropy, bf_entropy)

    score = entropy_to_score(final_entropy)
    times = crack_times(final_entropy)

    return PasswordResult(
        password=password,
        score=score,
        entropy=final_entropy,
        crack_time_estimates=times,
        optimal_matches=optimal,
        all_matches=all_matches,
        warnings=[],   # filled by feedback engine
        suggestions=[], # filled by recommendation engine
    )
