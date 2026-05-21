"""Password Checker — web UI + REST API."""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import secrets
import sys
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for

from config import BASE_DIR, load_config, path_from_config, secret_key
from decode import decode_password_candidates
from indexer import clear_cache, iter_list_files, prebuild_folder, rg_available, read_context_lines
from scanner import bulk_check_file, download_small_lists, run_full_check

app = Flask(__name__)
logger = logging.getLogger(__name__)
AUDIT_LOG = BASE_DIR / ".cache" / "audit.log"
HISTORY_FILE = BASE_DIR / ".cache" / "history.json"

SCAN_OPTION_MAP = {
    "case_insensitive": "case_insensitive",
    "variants": "check_variants",
    "hibp": "check_hibp",
    "local": "check_local",
    "hashes": "check_hashes",
    "online": "check_online",
    "fast": "fast_profile",
    "only_hibp": "only_hibp",
    "substring": "check_substring",
    "privacy": "privacy_mode",
    "stop_early": "stop_on_first_match",
}


def _cfg() -> dict:
    return load_config()


def _apply_scan_options(cfg: dict, opts: dict) -> None:
    scan = cfg.setdefault("scan", {})
    for api_key, cfg_key in SCAN_OPTION_MAP.items():
        if api_key in opts:
            scan[cfg_key] = bool(opts[api_key])


def _csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def _csrf_post(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.form.get("csrf") != session.get("csrf"):
            flash("Sessie verlopen.")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


@app.before_request
def _local_only():
    if not _cfg().get("app", {}).get("local_only", True):
        return
    if request.endpoint and request.endpoint.startswith("static"):
        return
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def _audit(found: bool, sources: list) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    types = ",".join(s.get("type", "?") for s in sources)
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} found={found} sources={types}\n")


def _history_append(found: bool) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    hist = json.loads(HISTORY_FILE.read_text(encoding="utf-8")) if HISTORY_FILE.is_file() else []
    hist.append({"time": datetime.now().isoformat(), "found": found})
    HISTORY_FILE.write_text(json.dumps(hist[-50:]), encoding="utf-8")


def _preview_html(match: dict | None, lists_dir: Path, context: int) -> str:
    if not match or not match.get("file_name"):
        return ""
    path = lists_dir / match["file_name"]
    if not path.is_file() and match.get("file_path"):
        path = Path(match["file_path"])
    if not path.is_file():
        return ""
    line_num = match.get("line_number", 1)
    return "".join(
        f'<div class="{"match-line" if i == line_num else "line"}"><strong>{i}:</strong> {html.escape(t)}</div>'
        for i, t in read_context_lines(path, line_num, context)
    )


def _run_check(password: str, opts: dict) -> dict:
    if not password.strip():
        return {"ok": False, "found": False, "status": "FOUT", "messages": ["Leeg wachtwoord."]}

    cfg = _cfg()
    _apply_scan_options(cfg, opts)
    passwords = decode_password_candidates(password) if opts.get("encoded") else [password]

    dirs = {k: path_from_config(cfg, k) for k in ("lists_dir", "hashes_dir", "cache_dir")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    result = run_full_check(password, lists_dir=dirs["lists_dir"], hashes_dir=dirs["hashes_dir"], cache_dir=dirs["cache_dir"], cfg=cfg, decoded_passwords=passwords)
    _audit(result["found"], result.get("sources", []))
    _history_append(result["found"])

    preview = ""
    if result.get("match") and not cfg.get("scan", {}).get("privacy_mode"):
        preview = _preview_html(result["match"], dirs["lists_dir"], cfg.get("index", {}).get("preview_context_lines", 5))

    return {**result, "ok": True, "preview_html": preview}


def _status_payload() -> dict:
    cfg = _cfg()
    lists_dir, hashes_dir, cache_dir = (path_from_config(cfg, k) for k in ("lists_dir", "hashes_dir", "cache_dir"))
    cache_mb = round(sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file()) / 1048576, 2) if cache_dir.is_dir() else 0
    recent = []
    if HISTORY_FILE.is_file():
        try:
            recent = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))[-10:]
        except json.JSONDecodeError:
            pass
    return {
        "ok": True,
        "version": cfg["app"].get("version", "3.0"),
        "ripgrep": bool(rg_available()),
        "lists_count": len(list(iter_list_files(lists_dir))) if lists_dir.is_dir() else 0,
        "hashes_count": len(list(iter_list_files(hashes_dir))) if hashes_dir.is_dir() else 0,
        "cache_mb": cache_mb,
        "recent_checks": recent,
    }


@app.route("/")
def index():
    cfg = _cfg()
    return render_template("index.html", csrf=_csrf_token(), version=cfg["app"].get("version", "3.0"))


@app.route("/api/status")
def api_status():
    return jsonify(_status_payload())


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()
    if not password:
        return jsonify({"ok": False, "error": "password required"}), 400
    try:
        return jsonify(_run_check(password, data))
    except Exception:
        logger.exception("API check failed")
        return jsonify({"ok": False, "error": "Check failed"}), 500


@app.route("/prebuild", methods=["POST"])
@_csrf_post
def prebuild():
    cfg, cache = _cfg(), path_from_config(_cfg(), "cache_dir")
    msgs = []
    for folder, kind, ci in [(path_from_config(cfg, "lists_dir"), "plain", True), (path_from_config(cfg, "hashes_dir"), "hash", False)]:
        if folder.is_dir():
            msgs.extend(prebuild_folder(folder, cache, kind, ci))
    flash("; ".join(msgs[:6]) + ("…" if len(msgs) > 6 else ""))
    return redirect(url_for("index"))


@app.route("/download_lists", methods=["POST"])
@_csrf_post
def download_lists_route():
    cfg = _cfg()
    dl = cfg.get("download", {})
    flash(" ".join(download_small_lists(cfg.get("small_lists_download", []), path_from_config(cfg, "lists_dir"), path_from_config(cfg, "cache_dir"), dl.get("timeout", 30), dl.get("retries", 3))[:8]))
    return redirect(url_for("index"))


@app.route("/clear_cache", methods=["POST"])
@_csrf_post
def clear_cache_route():
    flash(f"Cache gewist: {', '.join(clear_cache(path_from_config(_cfg(), 'cache_dir'))) or 'leeg'}")
    return redirect(url_for("index"))


@app.route("/bulk", methods=["POST"])
@_csrf_post
def bulk():
    f = request.files.get("file")
    if not f:
        flash("Geen bestand gekozen.")
        return redirect(url_for("index"))
    cfg = _cfg()
    cache = path_from_config(cfg, "cache_dir")
    upload = cache / "bulk_upload.txt"
    f.save(upload)
    out = cache / f"bulk_report_{int(time.time())}.csv"
    bulk_check_file(upload, path_from_config(cfg, "lists_dir"), path_from_config(cfg, "hashes_dir"), cache, cfg, out)
    flash(f"Rapport: {out.name}")
    return redirect(url_for("index"))


def cli_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Password Checker")
    p.add_argument("--build-index", metavar="FOLDER")
    p.add_argument("--check", metavar="PASSWORD")
    p.add_argument("--bulk", metavar="FILE")
    p.add_argument("--clear-cache", action="store_true")
    p.add_argument("--privacy", action="store_true")
    args, _ = p.parse_known_args(argv)

    cfg, cache = _cfg(), path_from_config(_cfg(), "cache_dir")
    lists, hashes = path_from_config(cfg, "lists_dir"), path_from_config(cfg, "hashes_dir")
    cache.mkdir(parents=True, exist_ok=True)

    if args.clear_cache:
        print("Cache:", ", ".join(clear_cache(cache)) or "empty")
        return 0
    if args.build_index:
        kind = "hash" if "hash" in Path(args.build_index).name.lower() else "plain"
        print("\n".join(prebuild_folder(Path(args.build_index), cache, kind, kind == "plain")))
        return 0
    if args.bulk:
        out = cache / "bulk_report.csv"
        bulk_check_file(Path(args.bulk), lists, hashes, cache, cfg, out)
        print(f"Report: {out}")
        return 0
    if args.check:
        r = _run_check(args.check, {"privacy": args.privacy})
        print(r["status"])
        print("\n".join(r["messages"]))
        return 1 if r["found"] else 0
    return -1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cfg = _cfg()
    app.secret_key = secret_key(cfg)
    rc = cli_main(sys.argv[1:])
    if rc == -1:
        debug = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
        app.run(host=cfg["app"].get("host", "127.0.0.1"), port=int(cfg["app"].get("port", 5000)), debug=debug, use_reloader=debug)
    sys.exit(max(rc, 0))
