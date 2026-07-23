"""Configuration (INI) -- so a distributor can ship the exe pre-pointed at their server.

Resolution order for the corpus server URL (first wins):
  1. $SPIEYES_SERVER              (env override, for dev)
  2. spi-eyes.ini next to the exe / in the cwd   (what a shipper drops beside SPI-Eyes.exe)
  3. spi-eyes.ini bundled inside the exe          (baked in at build time)
  4. built-in default (http://127.0.0.1:8787)

Ship `spi-eyes.ini` alongside SPI-Eyes.exe to lock clients to your server, e.g.:
    [server]
    url = http://corpus.yourorg.net:8787
"""
from __future__ import annotations

import configparser
import os
import sys
from typing import Optional, Tuple

DEFAULT_SERVER = "http://127.0.0.1:8787"
INI_NAME = "spi-eyes.ini"


def _app_dir() -> str:
    if getattr(sys, "frozen", False):                 # PyInstaller exe -> next to the .exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root


def _bundled_dir() -> str:
    return getattr(sys, "_MEIPASS", _app_dir())       # bundled-data dir when frozen


def _candidates() -> list:
    seen, out = set(), []
    for d in (os.getcwd(), _app_dir(), _bundled_dir()):
        p = os.path.join(d, INI_NAME)
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _load() -> Tuple[configparser.ConfigParser, Optional[str]]:
    cp = configparser.ConfigParser()
    for p in _candidates():
        if os.path.isfile(p):
            try:
                cp.read(p, encoding="utf-8")
                return cp, p
            except (OSError, configparser.Error):
                continue
    return cp, None


def server_url() -> str:
    env = os.environ.get("SPIEYES_SERVER")
    if env:
        return env.strip().rstrip("/")
    cp, _ = _load()
    if cp.has_option("server", "url"):
        val = cp.get("server", "url").strip().rstrip("/")
        if val:
            return val
    return DEFAULT_SERVER


def config_path() -> Optional[str]:
    return _load()[1]


def get(section: str, option: str, default=None):
    cp, _ = _load()
    return cp.get(section, option, fallback=default) if cp.has_section(section) else default
