import sys
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dashboard.data_access import read_query, open_readonly, sqlite_uri


def test_read_query_from_database(tmp_path):
    db = tmp_path / "test.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE sample (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO sample VALUES (1, 'test')")

    frame = read_query("SELECT * FROM sample", database=db)
    assert len(frame) == 1
    assert frame.iloc[0]["name"] == "test"


def test_database_connection_is_read_only(tmp_path):
    db = tmp_path / "test.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE sample (id INTEGER)")

    connection = open_readonly(db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("INSERT INTO sample VALUES (1)")
    finally:
        connection.close()


def test_missing_database_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_query("SELECT 1", database=tmp_path / "missing.db")


def test_sqlite_uri_uses_read_only_mode(tmp_path):
    uri = sqlite_uri(tmp_path / "test.db")
    assert uri.startswith("file:")
    assert uri.endswith("?mode=ro")
