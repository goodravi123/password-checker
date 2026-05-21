"""Configuration from config.yaml + environment."""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "app": {"host": "127.0.0.1", "port": 5000, "version": "3.0.0", "local_only": True},
        "paths": {"lists_dir": "lists", "hashes_dir": "hashes", "cache_dir": ".cache"},
        "scan": {"case_insensitive": True, "stop_on_first_match": True, "check_hibp": True},
    }
    if CONFIG_PATH.is_file():
        with CONFIG_PATH.open(encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
        for key, value in loaded.items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key] = {**cfg[key], **value}
            else:
                cfg[key] = value
    return cfg


def secret_key(cfg: dict[str, Any] | None = None) -> str:
    env = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if env:
        return env
    key = (cfg or load_config()).get("app", {}).get("secret_key", "")
    if key and key != "change-me-in-production":
        return key
    return secrets.token_hex(32)


def path_from_config(cfg: dict[str, Any], key: str) -> Path:
    return BASE_DIR / cfg["paths"][key]
