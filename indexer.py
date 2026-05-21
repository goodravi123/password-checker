"""Fast indexing: per-file SQLite, merged folder index, bloom filters, ripgrep."""

from __future__ import annotations

import gzip
import hashlib
import logging
import pickle
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)

BATCH_SIZE = 25_000
LIST_EXTENSIONS = {".txt", ".lst", ".gz"}
_HASH_LINE = re.compile(
    r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}):(.+)$"
)
_RG_PATH: str | None | bool = False


def file_signature(path: Path) -> str:
    stat = path.stat()
    return f"{path.resolve()}|{stat.st_mtime_ns}|{stat.st_size}"


def folder_signature(folder: Path, extensions: set[str] | None = None) -> str:
    exts = extensions or LIST_EXTENSIONS
    parts = []
    for p in sorted(iter_list_files(folder, exts)):
        parts.append(file_signature(p))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def iter_list_files(folder: Path, extensions: set[str] | None = None) -> Iterator[Path]:
    exts = extensions or LIST_EXTENSIONS
    if not folder.is_dir():
        return
    for p in sorted(folder.iterdir()):
        if p.is_file() and p.suffix.lower() in exts:
            yield p


def open_list_file(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def parse_line(line: str, kind: str) -> tuple[str | None, str | None]:
    """Return (lookup_key, display_value) for plain or hash indexes."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, None

    m = _HASH_LINE.match(stripped)
    if m:
        hash_part, plain = m.group(1), m.group(2)
        if kind == "plain":
            return plain, plain
        return hash_part.lower(), hash_part

    if ":" in stripped and kind == "plain":
        left, right = stripped.split(":", 1)
        if re.fullmatch(r"[\$./A-Za-z0-9]+", left) and len(left) >= 8 and right:
            return right, right

    if kind == "hash":
        if stripped.startswith("$2"):
            return stripped, stripped
        if re.fullmatch(r"[a-fA-F0-9]{32}(:[a-fA-F0-9]{32})?", stripped):
            return stripped.lower(), stripped
        return None, None

    return stripped, stripped


class BloomFilter:
    """Simple bloom filter for fast negative lookups."""

    def __init__(self, size: int, hash_count: int = 7):
        self.size = max(size, 64)
        self.hash_count = hash_count
        self.bits = bytearray((self.size + 7) // 8)

    def _indexes(self, item: str) -> list[int]:
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        idx = []
        for i in range(self.hash_count):
            combined = (h1 + i * h2) % self.size
            idx.append(combined)
        return idx

    def add(self, item: str):
        for i in self._indexes(item):
            self.bits[i // 8] |= 1 << (i % 8)

    def __contains__(self, item: str) -> bool:
        for i in self._indexes(item):
            if not (self.bits[i // 8] & (1 << (i % 8))):
                return False
        return True

    @classmethod
    def load(cls, path: Path) -> BloomFilter | None:
        if not path.is_file():
            return None
        try:
            with path.open("rb") as f:
                data = pickle.load(f)
            bf = cls(data["size"], data["hash_count"])
            bf.bits = data["bits"]
            return bf
        except Exception:
            return None

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            pickle.dump(
                {"size": self.size, "hash_count": self.hash_count, "bits": self.bits},
                f,
                protocol=pickle.HIGHEST_PROTOCOL,
            )


def rg_available() -> str | None:
    global _RG_PATH
    if _RG_PATH is False:
        _RG_PATH = shutil.which("rg")
    return _RG_PATH or None


def rg_lookup_single(source: Path, target: str, case_insensitive: bool) -> tuple[str, int] | None:
    rg = rg_available()
    if not rg:
        return None
    args = [rg, "-x", "-F", "-n", "--no-heading", "--no-messages"]
    if case_insensitive:
        args.append("-i")
    args.extend([target, str(source)])
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("ripgrep: %s", exc)
        return None
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return None
    first = proc.stdout.strip().splitlines()[0]
    parts = first.rsplit(":", 2)
    if len(parts) < 2:
        return None
    try:
        return parts[-1], int(parts[-2])
    except ValueError:
        return None


def sqlite_db_path(cache_dir: Path, path: Path) -> Path:
    digest = hashlib.sha256(file_signature(path).encode()).hexdigest()[:32]
    return cache_dir / "per_file" / f"{digest}.db"


def merged_db_path(cache_dir: Path, folder: Path, kind: str) -> Path:
    sig = folder_signature(folder)
    return cache_dir / "merged" / f"{kind}_{sig[:24]}.db"


def bloom_path(cache_dir: Path, path: Path) -> Path:
    digest = hashlib.sha256(file_signature(path).encode()).hexdigest()[:32]
    return cache_dir / "bloom" / f"{digest}.bloom"


def build_sqlite_index(
    source: Path, db_path: Path, kind: str, case_insensitive: bool
) -> bool:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = db_path.with_suffix(".tmp.db")
    if tmp.exists():
        tmp.unlink()
    collate = "NOCASE" if case_insensitive and kind == "plain" else "BINARY"
    try:
        conn = sqlite3.connect(tmp)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute(
            f"CREATE TABLE passwords (pwd TEXT NOT NULL COLLATE {collate} PRIMARY KEY, line_num INTEGER NOT NULL)"
        )
        batch: list[tuple[str, int]] = []
        with open_list_file(source) as f:
            for line_num, line in enumerate(f, 1):
                key, _ = parse_line(line, kind)
                if not key:
                    continue
                batch.append((key, line_num))
                if len(batch) >= BATCH_SIZE:
                    conn.executemany("INSERT OR IGNORE INTO passwords VALUES (?, ?)", batch)
                    batch.clear()
            if batch:
                conn.executemany("INSERT OR IGNORE INTO passwords VALUES (?, ?)", batch)
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO meta VALUES ('signature', ?)", (file_signature(source),))
        conn.execute("INSERT INTO meta VALUES ('kind', ?)", (kind,))
        conn.commit()
        conn.close()
        tmp.replace(db_path)
        return True
    except OSError as exc:
        logger.error("Index build failed %s: %s", source, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        return False


def build_bloom(source: Path, cache_dir: Path, min_bytes: int) -> BloomFilter | None:
    if source.stat().st_size < min_bytes:
        return None
    bf = BloomFilter(size=1 << 23)
    with open_list_file(source) as f:
        for line in f:
            key, _ = parse_line(line, "plain")
            if key:
                bf.add(key)
    bf.save(bloom_path(cache_dir, source))
    return bf


def build_merged_index(
    folder: Path, cache_dir: Path, kind: str, case_insensitive: bool
) -> Path | None:
    db_path = merged_db_path(cache_dir, folder, kind)
    sig = folder_signature(folder)
    if db_path.is_file():
        try:
            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT value FROM meta WHERE key='signature'").fetchone()
            conn.close()
            if row and row[0] == sig:
                return db_path
        except sqlite3.Error:
            pass

    files = list(iter_list_files(folder))
    if not files:
        return None

    tmp = db_path.with_suffix(".tmp.db")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    if tmp.exists():
        tmp.unlink()

    collate = "NOCASE" if case_insensitive and kind == "plain" else "BINARY"
    conn = sqlite3.connect(tmp)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute(
        f"""CREATE TABLE entries (
            pwd TEXT NOT NULL COLLATE {collate},
            source TEXT NOT NULL,
            line_num INTEGER NOT NULL,
            PRIMARY KEY (pwd, source)
        )"""
    )
    conn.execute("CREATE INDEX idx_pwd ON entries(pwd)")

    for source in files:
        batch: list[tuple[str, str, int]] = []
        with open_list_file(source) as f:
            for line_num, line in enumerate(f, 1):
                key, _ = parse_line(line, kind)
                if not key:
                    continue
                batch.append((key, source.name, line_num))
                if len(batch) >= BATCH_SIZE:
                    conn.executemany(
                        "INSERT OR IGNORE INTO entries VALUES (?, ?, ?)", batch
                    )
                    batch.clear()
        if batch:
            conn.executemany("INSERT OR IGNORE INTO entries VALUES (?, ?, ?)", batch)

    conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO meta VALUES ('signature', ?)", (sig,))
    conn.execute("INSERT INTO meta VALUES ('kind', ?)", (kind,))
    conn.commit()
    conn.close()
    tmp.replace(db_path)
    return db_path


def merged_lookup(
    folder: Path,
    cache_dir: Path,
    targets: set[str],
    kind: str,
    case_insensitive: bool,
) -> tuple[str, str, int] | None:
    db_path = build_merged_index(folder, cache_dir, kind, case_insensitive)
    if not db_path:
        return None
    try:
        conn = sqlite3.connect(db_path)
        placeholders = ",".join("?" * len(targets))
        row = conn.execute(
            f"SELECT pwd, source, line_num FROM entries WHERE pwd IN ({placeholders}) LIMIT 1",
            tuple(targets),
        ).fetchone()
        conn.close()
        if row:
            return row[0], row[1], row[2]
    except sqlite3.Error as exc:
        logger.warning("Merged lookup: %s", exc)
    return None


def per_file_lookup(
    source: Path,
    cache_dir: Path,
    targets: set[str],
    kind: str,
    case_insensitive: bool,
    bloom_min_bytes: int,
) -> tuple[str, int] | None:
    if not source.is_file() or not targets:
        return None

    bp = bloom_path(cache_dir, source)
    bf = BloomFilter.load(bp)
    if bf is None and source.stat().st_size >= bloom_min_bytes:
        bf = build_bloom(source, cache_dir, bloom_min_bytes)
    if bf:
        if not any(t in bf for t in targets):
            return None

    db_path = sqlite_db_path(cache_dir, source)
    if db_path.is_file():
        try:
            conn = sqlite3.connect(db_path)
            row = conn.execute("SELECT value FROM meta WHERE key='signature'").fetchone()
            if not row or row[0] != file_signature(source):
                conn.close()
            else:
                ph = ",".join("?" * len(targets))
                hit = conn.execute(
                    f"SELECT pwd, line_num FROM passwords WHERE pwd IN ({ph}) LIMIT 1",
                    tuple(targets),
                ).fetchone()
                conn.close()
                if hit:
                    return hit[0], hit[1]
        except sqlite3.Error:
            pass

    for target in sorted(targets, key=len, reverse=True):
        hit = rg_lookup_single(source, target, case_insensitive)
        if hit:
            build_sqlite_index(source, db_path, kind, case_insensitive)
            return hit

    with open_list_file(source) as f:
        compare = {t.lower() for t in targets} if case_insensitive else targets
        for line_num, line in enumerate(f, 1):
            key, _ = parse_line(line, kind)
            if not key:
                continue
            cmp = key.lower() if case_insensitive else key
            if cmp in compare:
                build_sqlite_index(source, db_path, kind, case_insensitive)
                for t in targets:
                    if (t.lower() if case_insensitive else t) == cmp:
                        return t, line_num
                return key, line_num
    return None


def lookup_in_folder(
    folder: Path,
    cache_dir: Path,
    targets: set[str],
    kind: str,
    case_insensitive: bool,
    bloom_min_bytes: int = 5_000_000,
    use_merged: bool = True,
) -> dict | None:
    if use_merged:
        hit = merged_lookup(folder, cache_dir, targets, kind, case_insensitive)
        if hit:
            return {
                "password": hit[0],
                "file_name": hit[1],
                "line_number": hit[2],
            }

    files = sorted(iter_list_files(folder), key=lambda p: p.stat().st_size)
    for path in files:
        result = per_file_lookup(
            path, cache_dir, targets, kind, case_insensitive, bloom_min_bytes
        )
        if result:
            return {
                "password": result[0],
                "file_name": path.name,
                "line_number": result[1],
                "file_path": str(path),
            }
    return None


def prebuild_folder(
    folder: Path,
    cache_dir: Path,
    kind: str = "plain",
    case_insensitive: bool = True,
) -> list[str]:
    messages = []
    files = sorted(iter_list_files(folder), key=lambda p: p.stat().st_size)
    for path in files:
        db_path = sqlite_db_path(cache_dir, path)
        if db_path.is_file():
            try:
                conn = sqlite3.connect(db_path)
                row = conn.execute("SELECT value FROM meta WHERE key='signature'").fetchone()
                conn.close()
                if row and row[0] == file_signature(path):
                    messages.append(f"[SKIP] {path.name}")
                    continue
            except sqlite3.Error:
                pass
        messages.append(f"[BUILD] {path.name}")
        ok = build_sqlite_index(path, db_path, kind, case_insensitive)
        messages.append("  -> ok" if ok else "  -> failed")
    messages.append("[MERGE] Building combined index...")
    merged = build_merged_index(folder, cache_dir, kind, case_insensitive)
    messages.append(f"  -> {'ok' if merged else 'skipped'}")
    return messages


def read_context_lines(path: Path, line_number: int, context: int = 5) -> list[tuple[int, str]]:
    start = max(1, line_number - context)
    end = line_number + context
    lines: list[tuple[int, str]] = []
    with open_list_file(path) as f:
        for i, line in enumerate(f, 1):
            if i < start:
                continue
            if i > end:
                break
            lines.append((i, line.rstrip()))
    return lines


def clear_cache(cache_dir: Path) -> list[str]:
    removed = []
    if cache_dir.is_dir():
        for child in cache_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
                removed.append(str(child.name))
            else:
                child.unlink(missing_ok=True)
                removed.append(child.name)
    return removed
