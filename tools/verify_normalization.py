"""Check frozen Step 2 normalization; never run sensors or connect to a database."""
from pathlib import Path
import hashlib
import json
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from spine.pipeline import normalize_record
from spine.storage import validate_record


def main():
    root = PROJECT / "tests/fixtures/synthetic_v1"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))
    if manifest.get("synthetic") is not True:
        raise ValueError("Expected synthetic fixtures")
    for name, expected in manifest["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Fixture path/hash mismatch: " + name)
    truth = json.loads((root / "ground-truth.json").read_text(encoding="utf-8-sig"))
    if truth.get("synthetic") is not True or not truth["source_scope"].startswith("synthetic/"):
        raise ValueError("Missing synthetic provenance")
    records = {}
    integrity = []
    for entry in truth["inputs"]:
        if entry["file"] not in manifest["files"] or entry["fixture_id"] in records:
            raise ValueError("Unexpected or repeated fixture identity")
        text = (root / entry["file"]).read_text(encoding="utf-8")
        raw = text if entry["line"] is None else text.splitlines()[entry["line"] - 1]
        options = {"input_format": entry["input_format"], "source_scope": entry["source_scope"],
                   "source_record_id": entry["source_record_id"], "observed_time": truth["observed_time"]}
        first, replay = normalize_record(raw, **options), normalize_record(raw, **options)
        validate_record(first)
        validate_record(replay)
        passed = (first["raw"]["text"] == raw and
                  first["raw"]["sha256"] == hashlib.sha256(raw.encode("utf-8")).hexdigest() and
                  first["record_id"] == replay["record_id"] and first["raw"] == replay["raw"])
        integrity.append(passed)
        records[entry["fixture_id"]] = first
    results = []
    for scenario in truth["scenarios"]:
        checks = []
        for requirement in scenario["field_checks"]:
            actual = records[requirement["fixture_id"]]
            for key in requirement["path"]:
                actual = actual[key]
            checks.append({"name": requirement["name"], "pass": actual == requirement["expected"]})
        results.append({"scenario": scenario["name"], "pass": all(c["pass"] for c in checks), "checks": checks})
    passed = all(integrity) and all(s["pass"] for s in results)
    print(json.dumps({"status": "PASS" if passed else "FAIL", "synthetic": True,
                      "live_sensors_executed": False, "database_accessed": False,
                      "association_evaluated": False, "records": len(records),
                      "raw_and_replay_checks_passed": sum(integrity),
                      "field_checks": sum(len(s["checks"]) for s in results), "scenarios": results}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
