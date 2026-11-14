"""Describe old unavailable EVE sources without discarding gap history."""

from datetime import date, timedelta
import os
from pathlib import Path
import re


RETENTION_DAYS = 14


def historical_missing_warning(path, *, directory, today=None, retention_days=RETENTION_DAYS):
    """Classify a missing dated security log beyond the documented window.

    This is an age-based classification, not proof of who deleted the file or
    that its final bytes were ingested. Call only after confirmed FileNotFound
    recovery and a successful directory inventory. Permission failures must
    remain current errors.
    """
    if type(retention_days) is not int or retention_days < 1:
        raise ValueError("retention_days must be a positive integer")
    today = date.today() if today is None else today
    if type(today) is not date:
        raise ValueError("today must be a date")
    candidate = Path(path)
    parent = os.path.normcase(str(candidate.parent.resolve()))
    expected = os.path.normcase(str(Path(directory).resolve()))
    if parent != expected:
        return None
    match = re.fullmatch(r"eve-(\d{4}-\d{2}-\d{2})\.json", candidate.name)
    if match is None:
        return None
    try:
        file_date = date.fromisoformat(match.group(1))
    except ValueError:
        return None
    # The observed Windows maintenance removed October 3 on October 17:
    # the dated 14-day boundary is eligible, not just strictly older dates.
    if file_date > today - timedelta(days=retention_days):
        return None
    return {
        "kind": "historical_source_unavailable",
        "file_path": str(candidate),
        "file_date": file_date.isoformat(),
        "retention_days": retention_days,
        "classification_basis": "filename_date_outside_retention_window",
        "deletion_cause": "not_established",
        "possible_evidence_gap": True,
        "gap_assessment": "Unread source data may be unavailable; extent is unknown",
        "checkpoint_preserved": True,
        "generation_retired": False,
    }
