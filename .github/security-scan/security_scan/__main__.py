"""Command-line entry point: ``python -m security_scan``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import date
from pathlib import Path

from security_scan.findings import (
    Finding,
    dedupe,
    parse_osv_scanner,
    parse_pip_audit,
)
from security_scan.ignore import apply_ignores, load_ignored_ids
from security_scan.issue import (
    ISSUE_TITLE,
    Action,
    GhIssueClient,
    IssueClient,
    decide,
    ids_from_body,
    render_body,
    render_comment,
)


def _parse(parser: Callable[[Path], list[Finding]], path: Path) -> list[Finding]:
    """Run a parser and name the file in the error when it cannot read it."""
    try:
        return parser(path)
    except (ValueError, KeyError) as exc:
        raise ValueError(f'{path.name} is not valid scanner output ({exc!r})') from exc


def run(
    osv_json: Path | None,
    pip_audit_jsons: Sequence[Path],
    toml_path: Path,
    client: IssueClient,
    run_url: str,
    today: date,
) -> Action:
    """Read the scanner output and bring the security issue up to date.

    Args:
        osv_json: ``osv-scanner`` JSON, or ``None`` when there was nothing to scan.
        pip_audit_jsons: One ``pip-audit`` JSON per audited requirements file.
        toml_path: ``osv-scanner.toml`` with the accepted risks.
        client: Where the issue lives.
        run_url: URL of the workflow run, linked from the issue.
        today: Current date, used for expiring ignores.

    Returns:
        The action that was taken.
    """
    findings = _parse(parse_osv_scanner, osv_json) if osv_json else []
    for path in pip_audit_jsons:
        findings += _parse(parse_pip_audit, path)
    findings = apply_ignores(dedupe(findings), load_ignored_ids(toml_path, today))

    issue = client.find_open()
    action = decide(issue, findings)
    if action == 'create':
        client.create(ISSUE_TITLE, render_body(findings, run_url))
    elif action == 'comment' and issue is not None:
        previous = ids_from_body(issue.body)
        client.update(issue.number, render_body(findings, run_url))
        client.comment(issue.number, render_comment(findings, previous, run_url))
    elif action == 'close' and issue is not None:
        client.close(
            issue.number,
            f'No open vulnerabilities in the latest scan. Closing. Run: {run_url}',
        )
    return action


def main(argv: Sequence[str] | None = None) -> int:
    """Parse the command line and run the scan report.

    Args:
        argv: Arguments; defaults to ``sys.argv[1:]``.

    Returns:
        0 on success; 2 when a scanner output that should exist is missing or
        unreadable (a tool failure, never "no vulnerabilities").
    """
    parser = argparse.ArgumentParser(prog='security_scan')
    parser.add_argument('--osv-json', type=Path)
    parser.add_argument('--pip-audit-json', type=Path, action='append', default=[])
    parser.add_argument('--toml', type=Path, default=Path('osv-scanner.toml'))
    parser.add_argument('--repo', required=True)
    parser.add_argument('--run-url', default='')
    args = parser.parse_args(argv)

    try:
        action = run(
            args.osv_json,
            args.pip_audit_json,
            args.toml,
            GhIssueClient(args.repo),
            args.run_url,
            date.today(),
        )
    except (OSError, ValueError, KeyError) as exc:
        print(f'security_scan: cannot read scanner output: {exc}', file=sys.stderr)
        return 2
    print(f'security_scan: {action}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
