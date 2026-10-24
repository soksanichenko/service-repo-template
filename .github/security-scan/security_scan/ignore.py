"""Accepted risks from ``osv-scanner.toml`` (``[[IgnoredVulns]]``)."""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from datetime import date
from pathlib import Path

from security_scan.findings import Finding


def _as_date(value: date | str) -> date:
    return value if isinstance(value, date) else date.fromisoformat(value)


def load_ignored_ids(path: Path, today: date) -> frozenset[str]:
    """Read the advisory ids that are still accepted.

    Args:
        path: Path of ``osv-scanner.toml``; a missing file means nothing is ignored.
        today: Current date; an entry whose ``ignoreUntil`` is before it has expired.

    Returns:
        Ids of the entries without ``ignoreUntil`` or with one that is not past.
    """
    if not path.exists():
        return frozenset()
    entries = tomllib.loads(path.read_text()).get('IgnoredVulns', [])
    return frozenset(
        entry['id']
        for entry in entries
        if 'ignoreUntil' not in entry or _as_date(entry['ignoreUntil']) >= today
    )


def apply_ignores(
    findings: Iterable[Finding], ignored: frozenset[str]
) -> list[Finding]:
    """Drop findings whose advisory is accepted.

    Args:
        findings: Findings to filter.
        ignored: Ids from ``load_ignored_ids``.

    Returns:
        Findings none of whose aliases is in ``ignored``.
    """
    return [f for f in findings if not ignored & set(f.aliases)]
