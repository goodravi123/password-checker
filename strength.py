"""Password strength estimation (entropy, patterns, optional zxcvbn)."""

from __future__ import annotations

import math
import re
from collections import Counter

KEYBOARD_PATTERNS = [
    "qwerty",
    "qwertyuiop",
    "asdfgh",
    "asdfghjkl",
    "zxcvbn",
    "123456",
    "12345678",
    "1234567890",
    "password",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
]


def shannon_entropy(password: str) -> float:
    if not password:
        return 0.0
    length = len(password)
    counts = Counter(password)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def has_keyboard_pattern(password: str) -> str | None:
    low = password.lower()
    for pat in KEYBOARD_PATTERNS:
        if pat in low or pat[::-1] in low:
            return pat
    return None


def basic_strength_score(password: str) -> dict:
    """Score 0-4 and human-readable feedback."""
    score = 0
    feedback: list[str] = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Te kort (minder dan 8 tekens).")

    if len(password) >= 12:
        score += 1

    classes = sum(
        [
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"[0-9]", password)),
            bool(re.search(r"[^A-Za-z0-9]", password)),
        ]
    )
    if classes >= 3:
        score += 1
    else:
        feedback.append("Weinig tekensoorten (hoofd/klein/cijfers/symbolen).")

    ent = shannon_entropy(password)
    if ent >= 3.5:
        score += 1
    else:
        feedback.append(f"Lage entropie ({ent:.2f} bits/char).")

    kb = has_keyboard_pattern(password)
    if kb:
        score = max(0, score - 1)
        feedback.append(f"Toetsenbordpatroon gedetecteerd: {kb}.")

    if re.fullmatch(r"(.)\1{3,}", password):
        score = max(0, score - 1)
        feedback.append("Herhaalde tekens.")

    labels = ["Zeer zwak", "Zwak", "Matig", "Sterk", "Zeer sterk"]
    label = labels[min(score, 4)]

    zxcvbn_result = None
    try:
        import zxcvbn

        z = zxcvbn.zxcvbn(password)
        zxcvbn_result = {
            "score": z["score"],
            "crack_time": z["crack_times_display"].get("offline_slow_hashing_1e4_per_second"),
            "warning": z.get("feedback", {}).get("warning"),
        }
        label = f"{label} (zxcvbn: {z['score']}/4)"
    except ImportError:
        pass

    return {
        "score": score,
        "label": label,
        "entropy": round(ent, 2),
        "length": len(password),
        "feedback": feedback,
        "zxcvbn": zxcvbn_result,
    }
