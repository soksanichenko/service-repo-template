"""Findings model and parsers for osv-scanner and pip-audit JSON output."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """One vulnerable package version.

    Attributes:
        package: Package name as reported by the scanner.
        version: Installed (locked or pinned) version.
        ecosystem: OSV ecosystem name, for example ``PyPI`` or ``npm``.
        id: CVE alias when there is one, otherwise the advisory id.
        aliases: Every id of the advisory, ``id`` first.
        severity: Highest CVSS score, or ``None`` when the scanner has none.
        fixed: Smallest version that fixes it, or ``None`` when none exists.
        source: Manifest the package was found in.
    """

    package: str
    version: str
    ecosystem: str
    id: str
    aliases: tuple[str, ...]
    severity: float | None
    fixed: str | None
    source: str


def _version_key(version: str) -> tuple[int, ...]:
    """Return a tolerant, comparable key for an arbitrary version string."""
    parts = re.findall(r'\d+|[A-Za-z]+', version)
    return tuple(int(p) if p.isdigit() else -1 for p in parts)


def _pick_id(ids: Iterable[str]) -> str:
    ids = list(ids)
    return next((i for i in ids if i.startswith('CVE-')), ids[0])


def _aliases(primary: str, others: Iterable[str]) -> tuple[str, ...]:
    rest = sorted({o for o in others if o != primary})
    return (primary, *rest)


def _fixed_version(vulns: Iterable[dict], package: str, ecosystem: str, version: str):
    """Smallest ``fixed`` event of the affected range that contains ``version``."""
    current = _version_key(version)
    fixes: list[str] = []
    for vuln in vulns:
        for affected in vuln.get('affected', []):
            info = affected.get('package', {})
            if info.get('name', '').lower() != package.lower():
                continue
            if info.get('ecosystem') != ecosystem:
                continue
            for rng in affected.get('ranges', []):
                if rng.get('type') not in ('ECOSYSTEM', 'SEMVER'):
                    continue
                introduced = None
                for event in rng.get('events', []):
                    if 'introduced' in event:
                        introduced = event['introduced']
                    elif 'fixed' in event and introduced is not None:
                        lower = _version_key(introduced)
                        if lower <= current < _version_key(event['fixed']):
                            fixes.append(event['fixed'])
                        introduced = None
    return min(fixes, key=_version_key) if fixes else None


def parse_osv_scanner(path: Path) -> list[Finding]:
    """Read ``osv-scanner --format json`` output.

    Args:
        path: JSON file written by ``osv-scanner scan source --format json``.

    Returns:
        One finding per advisory group of every vulnerable package.
    """
    data = json.loads(path.read_text())
    findings: list[Finding] = []
    for result in data.get('results', []):
        source = result['source']['path'].removeprefix('./')
        for pkg in result.get('packages', []):
            info = pkg['package']
            vulns = {v['id']: v for v in pkg.get('vulnerabilities', [])}
            for group in pkg.get('groups', []):
                every = [*group['ids'], *group.get('aliases', [])]
                primary = _pick_id(every)
                severity = (
                    float(group['max_severity']) if group.get('max_severity') else None
                )
                findings.append(
                    Finding(
                        package=info['name'],
                        version=info['version'],
                        ecosystem=info['ecosystem'],
                        id=primary,
                        aliases=_aliases(primary, every),
                        severity=severity,
                        fixed=_fixed_version(
                            [vulns[i] for i in group['ids'] if i in vulns],
                            info['name'],
                            info['ecosystem'],
                            info['version'],
                        ),
                        source=source,
                    )
                )
    return findings


def parse_pip_audit(path: Path) -> list[Finding]:
    """Read ``pip-audit -f json`` output.

    Args:
        path: JSON file written by ``pip-audit ... -f json -o <path>``.

    Returns:
        One finding per vulnerability of every audited dependency. ``source`` is
        the JSON file name because the report does not name the requirements file.
    """
    data = json.loads(path.read_text())
    findings: list[Finding] = []
    for dep in data.get('dependencies', []):
        for vuln in dep.get('vulns', []):
            every = [vuln['id'], *vuln.get('aliases', [])]
            primary = _pick_id(every)
            newer = [
                v
                for v in vuln.get('fix_versions', [])
                if _version_key(v) > _version_key(dep['version'])
            ]
            findings.append(
                Finding(
                    package=dep['name'],
                    version=dep['version'],
                    ecosystem='PyPI',
                    id=primary,
                    aliases=_aliases(primary, every),
                    severity=None,
                    fixed=min(newer, key=_version_key) if newer else None,
                    source=path.name,
                )
            )
    return findings


def _merge(first: Finding, second: Finding) -> Finding:
    severities = [s for s in (first.severity, second.severity) if s is not None]
    primary = _pick_id([*first.aliases, *second.aliases])
    return replace(
        first,
        id=primary,
        aliases=_aliases(primary, [*first.aliases, *second.aliases]),
        severity=max(severities) if severities else None,
        fixed=first.fixed or second.fixed,
    )


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings that describe the same advisory on the same package version.

    Args:
        findings: Findings from any number of scanners.

    Returns:
        Merged findings ordered by severity (highest first, unknown last).
    """
    merged: list[Finding] = []
    for finding in findings:
        current = finding
        changed = True
        while changed:
            changed = False
            for other in merged:
                same_package = (
                    other.package.lower() == current.package.lower()
                    and other.version == current.version
                )
                if same_package and set(other.aliases) & set(current.aliases):
                    merged.remove(other)
                    current = _merge(other, current)
                    changed = True
                    break
        merged.append(current)
    return sorted(
        merged,
        key=lambda f: (f.severity is None, -(f.severity or 0.0), f.package, f.id),
    )
