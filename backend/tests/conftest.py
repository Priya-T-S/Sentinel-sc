import os
import sys
import tempfile
from pathlib import Path

# Isolated data dir BEFORE importing sentinel (config reads it at import time)
_TMP = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ["SENTINEL_DATA_DIR"] = _TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from sentinel import db  # noqa: E402
from sentinel.config import DEMO_APP_DIR, FIXTURE_DIR  # noqa: E402
from sentinel.intel import load_fixture  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _db():
    db.init(Path(_TMP) / "test.db")
    load_fixture(FIXTURE_DIR / "intel-snapshot.json")
    yield


@pytest.fixture(scope="session")
def demo_result():
    """Offline (fixture-backed, deterministic) scan of the demo project."""
    from sentinel import engine
    from sentinel.reposource import DirSource
    return engine.run_scan(DirSource(str(DEMO_APP_DIR)), offline=True, scan_id="test")
