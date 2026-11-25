"""Explicit database connections for the SPINE Investigation Manager."""

from pathlib import Path

import psycopg


def connect_manager_database(
    *,
    dbname,
    password=None,
    passfile=None,
    host="127.0.0.1",
    port=5432,
    user="spine_app",
):
    """Connect using either an explicit password or a password file."""
    for name, value in (
        ("dbname", dbname),
        ("host", host),
        ("user", user),
    ):
        if (
            not isinstance(value, str)
            or not value.strip()
            or value != value.strip()
        ):
            raise ValueError(f"{name} must be nonempty, trimmed text")

    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")

    if passfile is not None:
        if password is not None:
            raise ValueError("Provide password or passfile, not both")

        if not isinstance(passfile, (str, Path)) or not str(passfile).strip():
            raise ValueError("A password-file path is required")

        credential_path = Path(passfile).expanduser().resolve()

        if not credential_path.is_file():
            raise ValueError("Database password file does not exist")

        authentication = {"passfile": str(credential_path)}
    else:
        if not isinstance(password, str) or not password:
            raise ValueError("A database password is required")

        authentication = {"password": password}

    connection = psycopg.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        connect_timeout=5,
        autocommit=True,
        application_name="spine_investigation_manager",
        **authentication,
    )

    try:
        connection.isolation_level = (
            psycopg.IsolationLevel.READ_COMMITTED
        )
        connection.execute("SET statement_timeout = '30s'")
        connection.execute("SET lock_timeout = '5s'")
        connection.execute(
            "SET idle_in_transaction_session_timeout = '60s'"
        )
    except Exception:
        connection.close()
        raise

    return connection