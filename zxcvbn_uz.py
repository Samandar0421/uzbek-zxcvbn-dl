"""
zxcvbn_uz.py
============
Main orchestrator for the Uzbek-localized zxcvbn password strength estimator.

Architecture:
  ┌──────────────────────────────────────────────────────┐
  │                    zxcvbn_uz                         │
  │                                                      │
  │  1. Input Phase     → collect user context          │
  │  2. Analysis Phase  → run all matchers              │
  │  3. Scoring Phase   → DP entropy calculation        │
  │  4. Feedback Phase  → Uzbek-language explanations   │
  │  5. Recommendation  → 3 secure alternatives         │
  └──────────────────────────────────────────────────────┘

Usage:
  python zxcvbn_uz.py                  # interactive mode
  python zxcvbn_uz.py --test           # run built-in test suite
"""

from __future__ import annotations
import sys
import argparse
from typing import Optional

# Core modules
from matchers import (
    dictionary_matcher,
    leet_matcher,
    date_matcher,
    spatial_matcher,
    contextual_matcher,
    Match,
)
from scorer import score_password, PasswordResult
from feedback import generate_feedback, recommend_passwords

# ---------------------------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------------------------

def analyze_password(
    password: str,
    user_context: Optional[dict[str, str]] = None,
) -> dict:
    """
    Full analysis pipeline. Returns a rich result dictionary.

    Parameters
    ----------
    password     : The password string to evaluate.
    user_context : Optional dict with keys like 'first_name', 'last_name',
                   'birth_year', 'city'.

    Returns
    -------
    dict with keys: score, entropy_bits, crack_times, warnings,
                    suggestions, detected_patterns, recommendations.
    """
    ctx = user_context or {}

    # ── Phase 2: Run all matchers ─────────────────────────────────────────
    all_matches: list[Match] = []
    all_matches.extend(dictionary_matcher(password))
    all_matches.extend(leet_matcher(password))
    all_matches.extend(date_matcher(password))
    all_matches.extend(spatial_matcher(password))
    if ctx:
        all_matches.extend(contextual_matcher(password, ctx))

    # ── Phase 3: Score ────────────────────────────────────────────────────
    result: PasswordResult = score_password(password, all_matches)

    # ── Phase 4: Feedback ─────────────────────────────────────────────────
    feedback = generate_feedback(result)

    # ── Phase 5: Recommendations ──────────────────────────────────────────
    recs = recommend_passwords(ctx, count=3)
    feedback["recommendations"] = recs

    return feedback


# ---------------------------------------------------------------------------
# DISPLAY
# ---------------------------------------------------------------------------

def _bar(score: int, width: int = 20) -> str:
    """Visual strength bar."""
    colors = ["🔴", "🟠", "🟡", "🟢", "✅"]
    filled = int((score + 1) / 5 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"{colors[score]} [{bar}]"


def display_result(password: str, result: dict) -> None:
    """Pretty-print the analysis result to the terminal."""
    label = result["score_label"]
    score = result["score"]

    print("\n" + "═" * 60)
    print(f"  🔐  PAROL TAHLILI")
    print("═" * 60)
    print(f"  Parol          : {'*' * len(password)}")
    print(f"  Daraja         : {label['color']} {label['uz'].upper()} (Score: {score}/4)")
    print(f"  Kuch darajasi  : {_bar(score)}")
    print(f"  Entropiya      : {result['entropy_bits']:.1f} bit")

    print("\n  ⏱️  Buzish vaqti taxmini:")
    ct = result["crack_times"]
    print(f"    • Onlayn (limit bilan)    : {ct['online_throttled']}")
    print(f"    • Onlayn (limitsiz)       : {ct['online_unthrottled']}")
    print(f"    • Oflayn (bcrypt/scrypt)  : {ct['offline_slow_bcrypt']}")
    print(f"    • Oflayn (GPU, MD5)       : {ct['offline_fast_gpu']}")

    if result.get("detected_patterns"):
        print("\n  🔍  Aniqlangan naqshlar:")
        for p in result["detected_patterns"]:
            print(f"    • [{p['pattern'].upper():<12}] '{p['token']}'"
                  f"  → {p['detail']}  ({p['entropy']:.1f} bit)")

    if result["warnings"]:
        print("\n  ⚠️   Ogohlantirishlar:")
        for w in result["warnings"]:
            print(f"    • {w}")

    if result["suggestions"]:
        print("\n  💡  Tavsiyalar:")
        for s in result["suggestions"]:
            print(f"    • {s}")

    if result.get("recommendations"):
        print("\n  🛡️   Xavfsiz muqobil parollar:")
        for i, rec in enumerate(result["recommendations"], 1):
            print(f"\n    {i}. {rec['strategy']}")
            print(f"       Parol : \033[1m{rec['password']}\033[0m")
            print(f"       Sabab : {rec['why_strong']}")

    print("\n" + "═" * 60 + "\n")


# ---------------------------------------------------------------------------
# INTERACTIVE INPUT PHASE
# ---------------------------------------------------------------------------

def _prompt_user_context() -> dict[str, str]:
    """Collect personal context from the user interactively."""
    print("\n" + "─" * 60)
    print("  👤  SHAXSIY MA'LUMOT (kontekstli tahlil uchun)")
    print("  (Ixtiyoriy — bo'sh qoldirish mumkin, Enter bosing)")
    print("─" * 60)

    fields = [
        ("first_name",  "Ismingiz       "),
        ("last_name",   "Familiyangiz   "),
        ("birth_year",  "Tug'ilgan yil  "),
        ("city",        "Shahar/Viloyat "),
    ]

    ctx: dict[str, str] = {}
    for key, label in fields:
        val = input(f"  {label}: ").strip()
        if val:
            ctx[key] = val
    return ctx


def interactive_mode() -> None:
    """Full interactive CLI session."""
    print("\n" + "═" * 60)
    print("  🔒  O'ZBEK ZXCVBN — Parol Kuch Tahlilchisi")
    print("  Toshkent Davlat Iqtisodiyot Universiteti")
    print("  Bitiruv Malakaviy Ishi — AT-62 guruh")
    print("═" * 60)

    user_context = _prompt_user_context()

    while True:
        print("\n" + "─" * 60)
        password = input("  Parolni kiriting (chiqish: 'q'): ").strip()
        if password.lower() in ("q", "quit", "exit", "chiqish"):
            print("\n  Dasturdan chiqildi. Xavfsiz parol saqlang! 🔐\n")
            break
        if not password:
            print("  ⚠️  Parol bo'sh. Qayta kiriting.")
            continue

        result = analyze_password(password, user_context)
        display_result(password, result)


# ---------------------------------------------------------------------------
# BUILT-IN TEST SUITE
# ---------------------------------------------------------------------------

TEST_CASES: list[dict] = [
    {
        "name": "Classic Uzbek name + year",
        "password": "Samandar2004",
        "context": {"first_name": "Samandar", "birth_year": "2004"},
        "expect_score_lte": 1,
    },
    {
        "name": "Leet-speak obfuscation",
        "password": "5@m4nd4r",
        "context": {"first_name": "Samandar"},
        "expect_score_lte": 2,
    },
    {
        "name": "Keyboard walk",
        "password": "qwerty123",
        "context": {},
        "expect_score_lte": 1,
    },
    {
        "name": "Common word + short year",
        "password": "sardor81",
        "context": {"first_name": "Sardor"},
        "expect_score_lte": 1,
    },
    {
        "name": "Sports team reference",
        "password": "Pakhtakor2024",
        "context": {},
        "expect_score_lte": 1,
    },
    {
        "name": "Strong passphrase (should score high)",
        "password": "Uchqur-Kerakli-Barqaror-!x9",
        "context": {},
        "expect_score_gte": 3,
    },
    {
        "name": "Full random 16-char",
        "password": "Kp#9mZqL!r2Nv5xW",
        "context": {},
        "expect_score_gte": 3,
    },
    {
        "name": "Surname only (familiya)",
        "password": "soliyev",
        "context": {"last_name": "Soliyev"},
        "expect_score_lte": 0,
    },
]


def run_tests() -> None:
    """Execute the built-in test suite and print results."""
    print("\n" + "═" * 60)
    print("  🧪  TEST SUITE — Uzbek zxcvbn")
    print("═" * 60)

    passed = 0
    failed = 0

    for i, tc in enumerate(TEST_CASES, 1):
        result = analyze_password(tc["password"], tc.get("context", {}))
        score = result["score"]

        ok = True
        if "expect_score_lte" in tc and score > tc["expect_score_lte"]:
            ok = False
        if "expect_score_gte" in tc and score < tc["expect_score_gte"]:
            ok = False

        status = "✅ PASSED" if ok else "❌ FAILED"
        if ok:
            passed += 1
        else:
            failed += 1

        label = result["score_label"]
        print(f"\n  [{i:02d}] {status}  — {tc['name']}")
        print(f"        Password  : {tc['password']}")
        print(f"        Score     : {score}/4 ({label['uz']}) | {result['entropy_bits']:.1f} bit")

        patterns = result.get("detected_patterns", [])
        if patterns:
            pnames = ", ".join(f"{p['pattern']}:{p['token']}" for p in patterns)
            print(f"        Detected  : {pnames}")

    print("\n" + "─" * 60)
    print(f"  Natija: {passed} ta o'tdi, {failed} ta muvaffaqiyatsiz")
    print("─" * 60 + "\n")


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Uzbek-localized zxcvbn password strength estimator"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run the built-in test suite",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Analyze a single password (non-interactive)",
    )
    parser.add_argument(
        "--name",
        type=str,
        default="",
        help="User's first name for context matching",
    )
    parser.add_argument(
        "--surname",
        type=str,
        default="",
        help="User's surname for context matching",
    )
    parser.add_argument(
        "--year",
        type=str,
        default="",
        help="User's birth year for context matching",
    )

    args = parser.parse_args()

    if args.test:
        run_tests()
        return

    if args.password:
        ctx = {}
        if args.name:    ctx["first_name"]  = args.name
        if args.surname: ctx["last_name"]   = args.surname
        if args.year:    ctx["birth_year"]  = args.year
        result = analyze_password(args.password, ctx)
        display_result(args.password, result)
        return

    # Default: interactive
    interactive_mode()


if __name__ == "__main__":
    main()
