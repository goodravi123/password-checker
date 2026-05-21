"""Password variant generation (leet, normalize, common mutations)."""

from __future__ import annotations

import re

LEET_MAP = str.maketrans(
    {
        "a": "@",
        "A": "@",
        "e": "3",
        "E": "3",
        "i": "1",
        "I": "1",
        "o": "0",
        "O": "0",
        "s": "$",
        "S": "$",
        "t": "7",
        "T": "7",
    }
)

REVERSE_LEET = {
    "@": "a",
    "3": "e",
    "1": "i",
    "0": "o",
    "$": "s",
    "7": "t",
}


def normalize_password(password: str) -> str:
    """Lowercase, strip edges, collapse internal whitespace."""
    return " ".join(password.strip().lower().split())


def deleet(password: str) -> str:
    out = []
    for ch in password:
        out.append(REVERSE_LEET.get(ch, ch))
    return "".join(out)


def without_trailing_digits(password: str) -> str | None:
    stripped = re.sub(r"[0-9!@#$%^&*._\-+]+$", "", password)
    return stripped if stripped and stripped != password else None


def without_symbols(password: str) -> str | None:
    letters = re.sub(r"[^A-Za-z0-9]", "", password)
    return letters if letters and letters != password else None


def generate_variants(password: str, case_insensitive: bool = True) -> list[str]:
    """Return unique candidate passwords to check against lists."""
    seen: set[str] = set()
    out: list[str] = []

    def add(value: str | None):
        if not value:
            return
        if value not in seen:
            seen.add(value)
            out.append(value)
        if case_insensitive:
            low = value.lower()
            if low not in seen:
                seen.add(low)
                out.append(low)

    add(password)
    add(normalize_password(password))
    add(deleet(password))
    add(password.translate(LEET_MAP))

    base = deleet(password)
    add(base)
    add(without_trailing_digits(password))
    add(without_trailing_digits(base))
    add(without_symbols(password))
    add(without_symbols(base))

    if len(password) > 1:
        add(password + "1")
        add(password + "!")
        add(password + "123")

    return out
