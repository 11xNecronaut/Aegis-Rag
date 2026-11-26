import warnings

import pytest

from app import config, db as dbmod, engine as eng, llm
from app.telemetry import Telemetry

warnings.filterwarnings("ignore", category=DeprecationWarning)

ALICE = {"user_id": "alice", "tenant_id": "tenant-alice"}
BOB = {"user_id": "bob", "tenant_id": "tenant-bob"}
SECRET_BOB = "BLUE-ORCHID-917"


class Lab:
    def __init__(self, tmp_path, controls, provider, **settings_kw):
        self.settings = config.Settings(controls=frozenset(controls), db_path=tmp_path / "t.db",
                                        log_path=tmp_path / "e.jsonl", llm_provider="sim", **settings_kw)
        self.db = dbmod.Database(self.settings.db_path)
        self.db.init()
        self.events: list[dict] = []
        self.engine = eng.Engine(self.settings, self.db, provider, Telemetry(sink=self.events.append, mode="test"))

    def types(self):
        return [e["event_type"] for e in self.events]

    def seed_bob(self):
        self.engine.ingest(BOB, "Launch Plan", f"Bob confidential launch project code is {SECRET_BOB}. Launch date is March 3.")


@pytest.fixture
def lab(tmp_path):
    def make(mode="layered", *, controls=None, provider=None, **kw):
        c = controls if controls is not None else config.MODES[mode]
        return Lab(tmp_path, c, provider or llm.SimProvider(1.0), **kw)
    return make
