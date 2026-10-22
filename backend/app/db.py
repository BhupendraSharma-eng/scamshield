"""SQLite persistence for scans (history, dashboard stats, cache)."""

import json
from typing import Any

import aiosqlite

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    channel TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    preview TEXT,
    verdict TEXT NOT NULL,
    risk REAL NOT NULL,
    category TEXT,
    decided_by TEXT,
    mode TEXT,
    total_ms REAL,
    result_json TEXT NOT NULL,
    llm_status TEXT NOT NULL DEFAULT 'skipped',
    llm_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_hash ON scans(input_hash);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""


async def init_db() -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def save_scan(result: dict[str, Any], input_hash: str, preview: str) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """INSERT INTO scans (id, channel, input_hash, preview, verdict, risk, category, decided_by,
                                  mode, total_ms, result_json, llm_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["scan_id"], result["channel"], input_hash, preview[:200], result["verdict"],
                result["risk"], result.get("category"), result.get("decided_by"), result.get("mode"),
                result["latency_ms"]["total"], json.dumps(result), result["llm"]["status"],
            ),
        )
        await db.commit()


async def update_llm(scan_id: str, status: str, result: dict[str, Any]) -> None:
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            "UPDATE scans SET llm_status = ?, llm_json = ?, result_json = ?, verdict = ?, risk = ?, decided_by = ? WHERE id = ?",
            (status, json.dumps(result["llm"]), json.dumps(result), result["verdict"], result["risk"],
             result.get("decided_by"), scan_id),
        )
        await db.commit()


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,))
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


async def find_by_hash(input_hash: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(settings.db_path) as db:
        cur = await db.execute(
            "SELECT result_json FROM scans WHERE input_hash = ? ORDER BY created_at DESC LIMIT 1", (input_hash,)
        )
        row = await cur.fetchone()
    return json.loads(row[0]) if row else None


async def list_scans(limit: int = 50, channel: str | None = None, verdict: str | None = None) -> list[dict[str, Any]]:
    q, args = "SELECT id, created_at, channel, preview, verdict, risk, category, decided_by, mode, total_ms, llm_status FROM scans", []
    where = []
    if channel:
        where.append("channel = ?"); args.append(channel)
    if verdict:
        where.append("verdict = ?"); args.append(verdict)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(q, args)
        return [dict(r) for r in await cur.fetchall()]


async def stats() -> dict[str, Any]:
    async with aiosqlite.connect(settings.db_path) as db:
        async def grouped(col: str) -> dict[str, int]:
            cur = await db.execute(f"SELECT {col}, COUNT(*) FROM scans GROUP BY {col}")
            return {str(k): v for k, v in await cur.fetchall()}

        cur = await db.execute("SELECT COUNT(*), AVG(total_ms) FROM scans")
        total, avg_ms = await cur.fetchone()
        return {
            "total": total,
            "avg_latency_ms": round(avg_ms or 0, 1),
            "by_verdict": await grouped("verdict"),
            "by_channel": await grouped("channel"),
            "by_category": await grouped("category"),
            "by_decided_by": await grouped("decided_by"),
        }
