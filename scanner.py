"""Scan orchestration: HIBP, local, online, hashes."""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from indexer import clear_cache, iter_list_files, lookup_in_folder, open_list_file, parse_line, per_file_lookup
from strength import basic_strength_score
from variants import generate_variants

logger = logging.getLogger(__name__)
USER_AGENT = "PasswordChecker/3.0"


def compute_hash_targets(passwords: list[str]) -> set[str]:
    out: set[str] = set()
    for pwd in passwords:
        b = pwd.encode("utf-8")
        for fn in (hashlib.md5, hashlib.sha1, hashlib.sha256):
            out.add(fn(b).hexdigest())
        try:
            out.add(hashlib.new("md4", b).hexdigest())
        except (ValueError, OSError):
            pass
    return {t.lower() for t in out}


def build_targets(passwords: list[str], case_insensitive: bool, use_variants: bool) -> set[str]:
    out: set[str] = set()
    for pwd in passwords:
        out.update(generate_variants(pwd, case_insensitive) if use_variants else [pwd, pwd.lower() if case_insensitive else pwd])
    return {x for x in out if x}


def check_hibp(password: str, timeout: int = 12, retries: int = 3) -> dict:
    digest = hashlib.sha1(password.encode()).hexdigest().upper()
    url = f"https://api.pwnedpasswords.com/range/{digest[:5]}"
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            with urlopen(Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
            for line in body.splitlines():
                part, _, count = line.partition(":")
                if part.strip() == digest[5:]:
                    n = count.strip()
                    return {"found": True, "source": "HIBP", "messages": [f"[HIBP] Gevonden in {n} datalek(ken)."]}
            return {"found": False, "messages": ["[HIBP] Niet in breach-database."]}
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = exc
            time.sleep(0.3 * attempt)
    return {"found": False, "messages": [f"[HIBP] Mislukt: {last_error}"]}


def check_hibp_parallel(passwords: list[str], case_insensitive: bool, use_variants: bool, timeout: int, retries: int) -> dict:
    targets = build_targets(passwords, case_insensitive, use_variants)
    messages: list[str] = []
    with ThreadPoolExecutor(max_workers=min(4, max(1, len(targets)))) as ex:
        futs = [ex.submit(check_hibp, t, timeout, retries) for t in targets]
        for fut in as_completed(futs):
            r = fut.result()
            messages.extend(r["messages"])
            if r["found"]:
                return {"found": True, "source": "HIBP", "messages": messages}
    return {"found": False, "messages": messages}


def _folder_scan(folder: Path, cache_dir: Path, targets: set[str], kind: str, case_insensitive: bool, bloom_min: int, label: str) -> dict:
    if not folder.is_dir():
        return {"found": False, "messages": [], "match": None}
    files = list(iter_list_files(folder))
    if not files:
        return {"found": False, "messages": [f"Geen lijstbestanden in {folder.name}/."], "match": None}
    match = lookup_in_folder(folder, cache_dir, targets, kind, case_insensitive, bloom_min)
    if match:
        return {
            "found": True,
            "messages": [f"[MATCH] {label} {match['file_name']} regel {match['line_number']}"],
            "match": match,
            "source": label,
        }
    return {"found": False, "messages": [f"[NO MATCH] Niet in {label.lower()}."], "match": None}


def substring_scan(folder: Path, passwords: list[str], privacy: bool) -> dict:
    messages = ["Substring-scan..."]
    for pwd in passwords:
        if len(pwd) < 4:
            continue
        low = pwd.lower()
        for path in iter_list_files(folder):
            with open_list_file(path) as f:
                for line_num, line in enumerate(f, 1):
                    entry, _ = parse_line(line, "plain")
                    if entry and low in entry.lower() and low != entry.lower():
                        msg = f"[SUBSTRING] In {path.name}:{line_num}" if privacy else f"[SUBSTRING] In '{entry}' ({path.name}:{line_num})"
                        return {"found": True, "messages": messages + [msg], "match": {"file_name": path.name, "line_number": line_num}, "source": "substring"}
    return {"found": False, "messages": messages + ["[NO MATCH] Geen substring-treffer."], "match": None}


def _url_cache_path(cache_dir: Path, url: str) -> Path:
    return cache_dir / "lists" / f"{hashlib.sha256(url.encode()).hexdigest()[:32]}.txt"


def download_url(url: str, cache_dir: Path, timeout: int, retries: int) -> Path | None:
    path = _url_cache_path(cache_dir, url)
    meta = path.with_suffix(".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and meta.is_file():
        try:
            if json.loads(meta.read_text(encoding="utf-8")).get("url") == url:
                return path
        except json.JSONDecodeError:
            pass
    for attempt in range(1, retries + 1):
        try:
            with urlopen(Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout) as resp:
                path.write_bytes(resp.read())
            meta.write_text(json.dumps({"url": url, "downloaded_at": time.time()}), encoding="utf-8")
            return path
        except (HTTPError, URLError, TimeoutError, OSError):
            time.sleep(0.3 * attempt)
    return None


def scan_online(urls: list[str], cache_dir: Path, targets: set[str], case_insensitive: bool, dl: dict) -> dict:
    timeout, retries, workers = dl.get("timeout", 30), dl.get("retries", 3), dl.get("workers", 4)
    ordered = sorted(urls, key=lambda u: _url_cache_path(cache_dir, u).stat().st_size if _url_cache_path(cache_dir, u).is_file() else 10**12)
    missing = [u for u in ordered if not _url_cache_path(cache_dir, u).is_file()]
    messages = ["Online lijsten..."]
    if missing:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(lambda u: download_url(u, cache_dir, timeout, retries), missing))
    bloom = 5_000_000
    for url in ordered:
        path = _url_cache_path(cache_dir, url)
        if not path.is_file():
            continue
        hit = per_file_lookup(path, cache_dir, targets, "plain", case_insensitive, bloom)
        if hit:
            return {"found": True, "messages": messages + [f"[MATCH] Online: {path.name}"], "match": {"file_name": path.name, "line_number": hit[1]}, "source": "online"}
    return {"found": False, "messages": messages + ["[NO MATCH] Niet in online lijsten."], "match": None}


def download_small_lists(urls: list[str], lists_dir: Path, cache_dir: Path, timeout: int, retries: int) -> list[str]:
    lists_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for url in urls:
        name = url.rsplit("/", 1)[-1]
        dest = lists_dir / name
        if dest.is_file():
            out.append(f"[SKIP] {name}")
            continue
        src = download_url(url, cache_dir, timeout, retries)
        if src:
            dest.write_bytes(src.read_bytes())
            out.append(f"[OK] {name}")
        else:
            out.append(f"[FOUT] {name}")
    return out


def _privacy_messages(messages: list[str], privacy: bool, found: bool) -> list[str]:
    if not privacy:
        return messages
    safe = [m for m in messages if "[HIBP]" in m or "[STERKTE]" in m or "[NO MATCH]" in m or "[MODUS]" in m or "[FOUT]" in m]
    if found:
        safe.append("[MATCH] Wachtwoord gevonden (details verborgen).")
    return safe


def _result(found: bool, messages: list, sources: list, match, strength, privacy: bool) -> dict:
    return {
        "found": found,
        "status": "GEVONDEN" if found else "NIET GEVONDEN",
        "messages": _privacy_messages(messages, privacy, found),
        "sources": sources,
        "match": match,
        "strength": strength,
        "privacy": privacy,
    }


def _consume(state: dict, scan: dict) -> dict | None:
    """Merge scan result; return final result if we should stop early."""
    state["messages"].extend(scan["messages"])
    if scan.get("found"):
        state["found"] = True
        state["match"] = scan.get("match") or state["match"]
        state["sources"].append({"type": scan.get("source", "?")})
    if state["stop"] and state["found"]:
        return _result(state["found"], state["messages"], state["sources"], state["match"], state["strength"], state["privacy"])
    return None


def run_full_check(
    password: str,
    *,
    lists_dir: Path,
    hashes_dir: Path,
    cache_dir: Path,
    cfg: dict,
    decoded_passwords: list[str] | None = None,
) -> dict:
    passwords = decoded_passwords or [password]
    if not any(p.strip() for p in passwords):
        return _result(False, ["Leeg wachtwoord."], [], None, None, False)

    scan = cfg.get("scan", {})
    case_insensitive = scan.get("case_insensitive", True)
    use_variants = scan.get("check_variants", True)
    bloom_min = cfg.get("index", {}).get("bloom_min_bytes", 5_000_000)
    privacy = scan.get("privacy_mode", False)
    targets_plain = build_targets(passwords, case_insensitive, use_variants)

    state = {
        "found": False,
        "messages": [],
        "sources": [],
        "match": None,
        "strength": None if privacy else basic_strength_score(passwords[0]),
        "privacy": privacy,
        "stop": scan.get("stop_on_first_match", True),
    }
    if state["strength"]:
        state["messages"].append(f"[STERKTE] {state['strength']['label']} (entropy {state['strength']['entropy']})")

    if scan.get("check_hibp", True):
        if done := _consume(state, check_hibp_parallel(passwords, case_insensitive, use_variants, cfg.get("hibp", {}).get("timeout", 12), cfg.get("hibp", {}).get("retries", 3))):
            return done

    if scan.get("only_hibp"):
        state["messages"].append("[MODUS] Alleen HIBP.")
        return _result(state["found"], state["messages"], state["sources"], state["match"], state["strength"], privacy)

    if scan.get("check_local", True):
        if done := _consume(state, _folder_scan(lists_dir, cache_dir, targets_plain, "plain", case_insensitive, bloom_min, "Lokaal")):
            return done

    if scan.get("check_hashes", True):
        if done := _consume(state, _folder_scan(hashes_dir, cache_dir, compute_hash_targets(passwords), "hash", False, bloom_min, "Hash")):
            return done

    if scan.get("check_substring", False) and lists_dir.is_dir():
        if done := _consume(state, substring_scan(lists_dir, passwords, privacy)):
            return done

    if scan.get("check_online", False):
        urls = list(cfg.get("online_lists", []))
        if not scan.get("fast_profile"):
            urls.extend(cfg.get("online_lists_full", []))
        if done := _consume(state, scan_online(urls, cache_dir, targets_plain, case_insensitive, cfg.get("download", {}))):
            return done
        if not state["found"] and cfg.get("mirror_lists"):
            if done := _consume(state, scan_online(cfg["mirror_lists"], cache_dir, targets_plain, case_insensitive, cfg.get("download", {}))):
                return done

    return _result(state["found"], state["messages"], state["sources"], state["match"], state["strength"], privacy)


def bulk_check_file(path: Path, lists_dir: Path, hashes_dir: Path, cache_dir: Path, cfg: dict, output_csv: Path) -> Path:
    hide = cfg.get("scan", {}).get("privacy_mode", False)
    rows = []
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            pwd = line.strip()
            if pwd:
                r = run_full_check(pwd, lists_dir=lists_dir, hashes_dir=hashes_dir, cache_dir=cache_dir, cfg=cfg)
                rows.append(["***" if hide else pwd, r["status"], "; ".join(r["messages"][:3])])
    with output_csv.open("w", newline="", encoding="utf-8") as out:
        csv.writer(out).writerows([["password", "status", "summary"], *rows])
    return output_csv
