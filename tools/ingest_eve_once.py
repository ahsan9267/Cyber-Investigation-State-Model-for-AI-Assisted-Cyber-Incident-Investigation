"""Run bounded ingestion passes over dated Suricata security logs."""

import argparse
from datetime import datetime, timezone
import getpass
import json
from pathlib import Path
import re
import time

import psycopg

from spine.file_recovery import ingest_with_recovery


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--passes", type=int, default=1)
    parser.add_argument("--records-per-file", type=int, default=100)
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    if args.passes < 1 or args.records_per_file < 1:
        parser.error("Passes and records-per-file must be positive")
    if not 0 <= args.interval <= 60:
        parser.error("Interval must be between 0 and 60 seconds")

    folder = Path(r"C:\Program Files\Suricata\log")
    pattern = re.compile(r"eve-\d{4}-\d{2}-\d{2}\.json")
    password = getpass.getpass("spine_app password: ")

    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="spine",
        user="spine_app",
        password=password,
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED

        for pass_number in range(1, args.passes + 1):
            # Rescan each pass so new daily files can be discovered.
            files = sorted(
                path for path in folder.iterdir()
                if path.is_file() and pattern.fullmatch(path.name)
            )

            if not files:
                raise RuntimeError("No dated security EVE files found")

            print(
                f"Pass {pass_number}/{args.passes} "
                f"at {datetime.now(timezone.utc).isoformat()}",
                flush=True,
            )

            for path in files:
                result = ingest_with_recovery(
                    connection,
                    path,
                    source_scope="lab/windows-suricata",
                    max_records=args.records_per_file,
                )
                print(
                    json.dumps(
                        {"file": path.name, **result},
                        ensure_ascii=False,
                    ),
                    flush=True,
                )

            if pass_number < args.passes:
                time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped. Resume by running the command again.")