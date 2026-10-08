from pathlib import Path
import sqlite3

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "database" / "intel.db"


def sqlite_uri(database: Path) -> str:
    return Path(database).resolve().as_uri() + "?mode=ro"


def open_readonly(database: Path = DEFAULT_DB) -> sqlite3.Connection:
    database = Path(database)
    if not database.is_file():
        raise FileNotFoundError(f"Database not found: {database}")

    connection = sqlite3.connect(
        sqlite_uri(database),
        uri=True,
        timeout=10,
    )
    connection.execute("PRAGMA query_only=ON")
    return connection


def read_query(
    sql: str,
    params: tuple = (),
    database: Path = DEFAULT_DB,
) -> pd.DataFrame:
    connection = open_readonly(database)
    try:
        return pd.read_sql_query(sql, connection, params=params)
    finally:
        connection.close()
