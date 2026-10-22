"""A rule update must not reuse persisted verdicts from the previous URL rules."""

import asyncio
import hashlib
import json
import sqlite3

from app import db
from app.engine.pipeline import input_hash
from app.schemas import Envelope


def test_url_rule_update_skips_old_cached_verdict_and_keeps_history(tmp_path, monkeypatch):
    monkeypatch.setattr(db.settings, "db_path", tmp_path / "scans.db")
    env = Envelope(channel="url", urls=["https://rntu.ac.in/"])
    legacy_key = "|".join(["url", "", "", "", env.urls[0], ""])
    legacy_hash = hashlib.sha256(legacy_key.encode()).hexdigest()

    async def check():
        await db.init_db()
        with sqlite3.connect(db.settings.db_path) as conn:
            conn.execute(
                "INSERT INTO scans (id, channel, input_hash, verdict, risk, result_json) VALUES (?, ?, ?, ?, ?, ?)",
                ("old", "url", legacy_hash, "SCAM", 0.8, json.dumps({"verdict": "SCAM"})),
            )
        assert await db.find_by_hash(input_hash(env)) is None
        assert await db.get_scan("old") == {"verdict": "SCAM"}

    asyncio.run(check())
