"""Render the security issue and drive its lifecycle through the gh CLI."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from security_scan.findings import Finding

ISSUE_TITLE = 'Security scan: open vulnerabilities'
LABEL = 'security-scan'
ROW_LIMIT = 50
MAX_IDS = 2000

Action = Literal['create', 'comment', 'close', 'none']

_IDS_MARKER = re.compile(r'<!-- security-scan-ids: ([^>]*?) -->')


@dataclass(frozen=True)
class Issue:
    """An open security issue.

    Attributes:
        number: Issue number.
        body: Current issue body.
    """

    number: int
    body: str


def decide(open_issue: Issue | None, findings: Sequence[Finding]) -> Action:
    """Choose what to do with the issue.

    Args:
        open_issue: The open ``security-scan`` issue, if any.
        findings: Findings that are still relevant after ignores.

    Returns:
        ``create``, ``comment``, ``close`` or ``none``.
    """
    if open_issue is None:
        return 'create' if findings else 'none'
    return 'comment' if findings else 'close'


def render_body(findings: Sequence[Finding], run_url: str) -> str:
    """Render the issue body.

    Args:
        findings: Findings ordered by severity.
        run_url: URL of the workflow run that produced them.

    Returns:
        Markdown with a table of at most ``ROW_LIMIT`` rows and a hidden marker
        listing every finding id (so later comments can tell what is new).
    """
    unfixed = sum(1 for f in findings if f.fixed is None)
    lines = [
        (
            f'The daily scan found {len(findings)} open vulnerabilities '
            f'({unfixed} without a fix). Last run: {run_url}'
        ),
        '',
        '| Package | Version | Advisory | CVSS | Fix |',
        '|---|---|---|---|---|',
    ]
    for f in findings[:ROW_LIMIT]:
        severity = '-' if f.severity is None else f'{f.severity:.1f}'
        fix = f.fixed or 'no fix available'
        lines.append(f'| `{f.package}` | {f.version} | {f.id} | {severity} | {fix} |')
    if len(findings) > ROW_LIMIT:
        lines += [
            '',
            (
                f'{len(findings) - ROW_LIMIT} more not shown, '
                f'{len(findings)} in total; see the run: {run_url}'
            ),
        ]
    ids = ','.join(f.id for f in findings[:MAX_IDS])
    lines += ['', f'<!-- security-scan-ids: {ids} -->']
    return '\n'.join(lines)


def ids_from_body(body: str) -> frozenset[str]:
    """Return the finding ids recorded in a body made by ``render_body``."""
    match = _IDS_MARKER.search(body)
    return (
        frozenset(match.group(1).split(','))
        if match and match.group(1)
        else frozenset()
    )


def render_comment(
    findings: Sequence[Finding], previous_ids: frozenset[str], run_url: str
) -> str:
    """Render the daily reminder comment.

    Args:
        findings: Current findings.
        previous_ids: Ids from the previous issue body.
        run_url: URL of the workflow run.

    Returns:
        A one-paragraph summary: still open, new, and without a fix.
    """
    still = sum(1 for f in findings if f.id in previous_ids)
    new = len(findings) - still
    unfixed = sum(1 for f in findings if f.fixed is None)
    return (
        f'Still open: {still}. New since the last scan: {new}. '
        f'Without a fix: {unfixed}. Run: {run_url}'
    )


class IssueClient(Protocol):
    """What the scan needs from GitHub issues."""

    def find_open(self) -> Issue | None: ...

    def create(self, title: str, body: str) -> int: ...

    def update(self, number: int, body: str) -> None: ...

    def comment(self, number: int, text: str) -> None: ...

    def close(self, number: int, text: str) -> None: ...


def _gh(args: list[str]) -> str:
    result = subprocess.run(['gh', *args], check=True, capture_output=True, text=True)
    return result.stdout


class GhIssueClient:
    """``IssueClient`` backed by the ``gh`` CLI and ``GITHUB_TOKEN``."""

    def __init__(self, repo: str, runner: Callable[[list[str]], str] = _gh) -> None:
        """Create the client.

        Args:
            repo: ``owner/name`` of the repository.
            runner: Runs ``gh`` with the given arguments and returns stdout;
                replaced by a fake in tests.
        """
        self.repo = repo
        self._runner = runner

    def _run(self, args: list[str]) -> str:
        try:
            return self._runner(args)
        except subprocess.CalledProcessError as exc:
            text = f'{exc.stderr or ""}{exc.output or ""}'
            if 'disabled' in text.lower():
                raise RuntimeError(
                    f'issues are disabled for {self.repo}; '
                    'enable them in the repository settings'
                ) from exc
            raise

    def find_open(self) -> Issue | None:
        """Return the open ``security-scan`` issue, if there is one."""
        out = self._run(
            [
                'issue',
                'list',
                '--repo',
                self.repo,
                '--label',
                LABEL,
                '--state',
                'open',
                '--json',
                'number,body',
                '--limit',
                '1',
            ]
        )
        items = json.loads(out or '[]')
        return Issue(items[0]['number'], items[0]['body']) if items else None

    def create(self, title: str, body: str) -> int:
        """Create the issue (and its label if missing); return its number."""
        self._run(
            [
                'label',
                'create',
                LABEL,
                '--repo',
                self.repo,
                '--force',
                '--color',
                'D93F0B',
                '--description',
                'Daily dependency security scan',
            ]
        )
        out = self._run(
            [
                'issue',
                'create',
                '--repo',
                self.repo,
                '--title',
                title,
                '--body',
                body,
                '--label',
                LABEL,
            ]
        )
        return int(out.strip().rsplit('/', 1)[-1])

    def update(self, number: int, body: str) -> None:
        """Replace the issue body."""
        self._run(['issue', 'edit', str(number), '--repo', self.repo, '--body', body])

    def comment(self, number: int, text: str) -> None:
        """Add a comment (this is what sends the email)."""
        self._run(
            ['issue', 'comment', str(number), '--repo', self.repo, '--body', text]
        )

    def close(self, number: int, text: str) -> None:
        """Close the issue with a final comment."""
        self._run(
            ['issue', 'close', str(number), '--repo', self.repo, '--comment', text]
        )
