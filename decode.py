"""Decode encoded password strings."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from urllib.parse import unquote, unquote_plus


def _valid_text(s: str) -> bool:
    if not s:
        return False
    for ch in s:
        o = ord(ch)
        if o < 32 or o >= 127 or not ch.isprintable():
            return False
    return True


def decode_password_candidates(encoded: str) -> list[str]:
    candidates = [encoded]
    seen = {encoded}

    def add(value: str):
        if value and _valid_text(value) and value not in seen:
            seen.add(value)
            candidates.append(value)

    try:
        if re.fullmatch(r"[0-9a-fA-F]+", encoded) and len(encoded) % 2 == 0:
            decoded = bytes.fromhex(encoded).decode("utf-8", errors="ignore")
            if _valid_text(decoded):
                add(decoded)
    except (ValueError, UnicodeDecodeError):
        pass

    for decoder in (unquote, unquote_plus):
        try:
            decoded = decoder(encoded)
            if decoded != encoded and _valid_text(decoded):
                add(decoded)
        except Exception:
            pass

    try:
        parts = [p for p in re.split(r"[\s,]+", encoded.strip()) if p]
        if parts and all(p.isdigit() for p in parts):
            add("".join(chr(int(p)) for p in parts))
    except (ValueError, OverflowError):
        pass

    try:
        if "\\u" in encoded.lower() or "u+" in encoded.lower():
            normalized = encoded.replace("U+", "\\u").replace("u+", "\\u")
            add(normalized.encode("utf-8").decode("unicode_escape"))
    except UnicodeDecodeError:
        pass

    try:
        import html as html_module

        decoded = html_module.unescape(encoded)
        if decoded != encoded and _valid_text(decoded):
            add(decoded)
    except Exception:
        pass

    try:
        padding = len(encoded) % 4
        encoded_mod = encoded + ("=" * (4 - padding) if padding else "")
        add(base64.b64decode(encoded_mod, validate=True).decode("utf-8", errors="ignore"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass

    try:
        padding = len(encoded) % 8
        encoded_mod = encoded.upper() + ("=" * (8 - padding) if padding else "")
        add(base64.b32decode(encoded_mod, casefold=True).decode("utf-8", errors="ignore"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        pass

    try:
        if re.fullmatch(r"[A-Za-z]+", encoded):
            add(codecs.decode(encoded, "rot_13"))
    except Exception:
        pass

    rev = encoded[::-1]
    if rev != encoded and _valid_text(rev):
        add(rev)

    return candidates
