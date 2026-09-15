from __future__ import annotations

import hashlib


def advisory_lock_key(lock_name: str) -> int:
    digest = hashlib.sha256(lock_name.encode("utf-8")).digest()
    key = int.from_bytes(digest[:8], byteorder="big", signed=False)
    if key >= 2**63:
        key -= 2**64
    return key


def try_advisory_lock(conn, lock_name: str) -> bool:
    key = advisory_lock_key(lock_name)
    with conn.cursor() as cur:
        cur.execute("select pg_try_advisory_lock(%s);", [key])
        return bool(cur.fetchone()[0])
