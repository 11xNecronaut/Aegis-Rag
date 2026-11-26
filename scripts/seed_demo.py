"""Seed the demo database. Does NOT wipe existing data unless --reset is passed."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config
from app.db import Database
from app.retrieval import HashingEmbedder
from attacks.corpus import BASE_DOCS


def seed(db: Database, reset: bool = False) -> int:
    db.init()
    if reset:
        db.clear_all()
    emb = HashingEmbedder()
    added = 0
    for user, title, content in BASE_DOCS:
        tenant = config.TENANTS[user]
        if any(d["title"] == title for d in db.list_documents(tenant)):
            continue  # idempotent
        db.add_document(tenant, title, content, embedder=emb)
        added += 1
    return added


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true", help="delete ALL existing data first")
    args = ap.parse_args()
    s = config.load_settings()
    n = seed(Database(s.db_path), args.reset)
    print(f"Seeded {n} documents into {s.db_path}" + (" (after reset)" if args.reset else ""))
    print("Demo tokens: alice-demo-token / bob-demo-token (lab only; refused when AEGIS_ENV=prod)")
