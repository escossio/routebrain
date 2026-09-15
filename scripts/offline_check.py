"""Offline syntax/import/unit checks; never a database or measurement smoke test."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
sys.dont_write_bytecode = True
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
os.environ["ROUTEBRAIN_EMBEDDING_PROVIDER"] = "none"
os.environ["DATABASE_URL"] = "postgresql://invalid.invalid/offline_checks_only"
for key in list(os.environ):
    if any(part in key for part in ("API_KEY", "PASSWORD", "TOKEN")):
        os.environ.pop(key, None)


def guard(event, args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError(f"Offline check blocked external action: {event}")


sys.addaudithook(guard)
import psycopg


def deny_database(*args, **kwargs):
    raise RuntimeError("Database access is forbidden in offline checks")


psycopg.connect = deny_database
for directory in ("app", "scripts", "tests"):
    for source in (ROOT / directory).rglob("*.py"):
        ast.parse(source.read_text(), filename=str(source))
print("SYNTAX_CHECK=PASS")
import app.api.main
print("API_IMPORT=PASS")
import pytest
raise SystemExit(pytest.main(["-q", "-p", "no:cacheprovider", "--tb=short", "tests"]))
