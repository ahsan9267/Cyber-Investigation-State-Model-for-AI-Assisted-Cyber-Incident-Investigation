"""Shared PostgreSQL connection for unattended SPINE collectors."""

import os
from pathlib import Path

import psycopg


def connect_database():
    appdata = os.environ.get("APPDATA")

    if not appdata:
        raise ValueError("APPDATA is unavailable for this Windows account")

    passfile = Path(appdata) / "SPINE" / "credentials" / "pgpass.conf"

    if not passfile.is_file():
        raise ValueError(
            "SPINE database credential file is missing for this account"
        )

    connection = psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="spine",
        user="spine_app",
        passfile=str(passfile),
        connect_timeout=5,
        autocommit=True,
    )

    connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
    return connection