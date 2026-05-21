from pathlib import Path

from decode import decode_password_candidates
from indexer import build_sqlite_index, lookup_in_folder, parse_line
from variants import generate_variants, normalize_password


def test_decode_base64():
    c = decode_password_candidates("aGVsbG8=")
    assert "hello" in c


def test_parse_hash_plain():
    key, val = parse_line("5baa61e4a7567e0017b0c132225742be8a:password", "plain")
    assert key == "password"


def test_variants():
    v = generate_variants("P@ssw0rd", True)
    assert "p@ssw0rd" in [x.lower() for x in v] or "password" in [x.lower() for x in v]


def test_index_and_lookup(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("foo\npassword123\n", encoding="utf-8")
    cache = tmp_path / "cache"
    from indexer import sqlite_db_path

    db = sqlite_db_path(cache, f)
    build_sqlite_index(f, db, "plain", True)
    hit = lookup_in_folder(tmp_path, cache, {"password123"}, "plain", True, 10**9, use_merged=False)
    assert hit is not None
