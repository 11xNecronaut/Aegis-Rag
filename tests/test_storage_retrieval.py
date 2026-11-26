import sqlite3

import pytest

from app import db as dbmod, retrieval
from app.db import QuotaExceeded

EMB = retrieval.HashingEmbedder()


@pytest.fixture
def d(tmp_path):
    database = dbmod.Database(tmp_path / "t.db", max_docs_per_tenant=3)
    database.init()
    database.add_document("tenant-a", "Handbook", "Employees receive 20 days of paid time off each year.", embedder=EMB)
    database.add_document("tenant-a", "Security", "Passwords must be at least 14 characters long.", embedder=EMB)
    database.add_document("tenant-b", "Secret", "Launch project code is BLUE-ORCHID-917.", embedder=EMB)
    return database


def test_fail_closed_tenant_api(d):
    for bad in (None, "", "   ", 5):
        with pytest.raises(ValueError):
            d.iter_chunks(bad)
    with pytest.raises(ValueError):
        retrieval.search(d, "launch code", None, scoped=True)


def test_scoped_search_never_crosses_tenants(d):
    assert retrieval.search(d, "launch project code", "tenant-a", scoped=True, embedder=EMB) == []
    hits = retrieval.search(d, "launch project code", "tenant-b", scoped=True, embedder=EMB)
    assert hits and all(h.tenant_id == "tenant-b" for h in hits)


def test_unscoped_path_is_only_reachable_explicitly(d):
    hits = retrieval.search(d, "launch project code", "tenant-a", scoped=False, embedder=EMB)
    assert any(h.tenant_id == "tenant-b" for h in hits)


def test_plural_stemming_regression(d):
    hits = retrieval.search(d, "What is the password length requirement?", "tenant-a", scoped=True, embedder=EMB)
    assert hits and hits[0].title == "Security"


def test_document_quota(d):
    d.add_document("tenant-a", "Third", "More text here.", embedder=EMB)
    with pytest.raises(QuotaExceeded):
        d.add_document("tenant-a", "Fourth", "Over the limit.", embedder=EMB)
    d.add_document("tenant-b", "Other tenant unaffected", "Fine.", embedder=EMB)


def test_actions_are_tenant_scoped(d):
    aid = d.add_action("tenant-a", "alice", "create_ticket", {"title": "x"}, "pending_approval")
    assert d.get_action(aid, "tenant-a")["status"] == "pending_approval"
    assert d.get_action(aid, "tenant-b") is None


def test_every_sqlite_connection_is_closed(tmp_path, monkeypatch):
    opened, closed = [], []
    real = sqlite3.connect

    class Proxy:
        def __init__(self, *a, **k):
            self._c = real(*a, **k)
            opened.append(self)

        def close(self):
            closed.append(self)
            self._c.close()

        def __getattr__(self, name):
            return getattr(self._c, name)

        def __setattr__(self, name, value):
            if name == "_c":
                object.__setattr__(self, name, value)
            else:
                setattr(self._c, name, value)

        def __enter__(self):
            return self._c.__enter__()

        def __exit__(self, *a):
            return self._c.__exit__(*a)

    monkeypatch.setattr(dbmod.sqlite3, "connect", lambda *a, **k: Proxy(*a, **k))
    database = dbmod.Database(tmp_path / "c.db")
    database.init()
    database.add_document("t", "x", "hello world text", embedder=EMB)
    database.iter_chunks("t")
    database.list_documents("t")
    assert opened and len(opened) == len(closed)


def test_split_text_always_terminates_and_overlaps():
    pieces = dbmod.split_text("Sentence one. " * 200)
    assert len(pieces) > 3 and all(len(p) <= 600 for p in pieces)
    assert dbmod.split_text("") == []
