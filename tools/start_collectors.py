"""Launch SPINE collectors independently of a terminal environment."""

import os
from pathlib import Path
import runpy
import sys
import traceback


PROJECT = Path(__file__).resolve().parents[1]


def main():
    os.chdir(PROJECT)
    sys.path.insert(0, str(PROJECT / "src"))

    # Supply streams when launched through pythonw.exe.
    with open(os.devnull, "w", encoding="utf-8") as sink:
        if sys.stdout is None:
            sys.stdout = sink
        if sys.stderr is None:
            sys.stderr = sink

        sys.argv = [
            str(PROJECT / "tools/run_collectors.py"),
            "--continuous",
            "--records-per-file",
            "1000",
            "--interval",
            "5",
        ]

        try:
            runpy.run_path(sys.argv[0], run_name="__main__")
        except Exception:
            error_path = PROJECT / "data/logs/launcher_error.log"
            error_path.parent.mkdir(parents=True, exist_ok=True)
            # Keep the most recent launcher failure.
            error_path.write_text(
                traceback.format_exc(),
                encoding="utf-8",
            )
            raise


if __name__ == "__main__":
    main()