import json
import subprocess

import pytest
from security_scan.findings import Finding
from security_scan.issue import (
    ISSUE_TITLE,
    LABEL,
    ROW_LIMIT,
    GhIssueClient,
    Issue,
    decide,
    ids_from_body,
    render_body,
    render_comment,
)

RUN_URL = 'https://github.com/o/r/actions/runs/1'


def finding(n: int = 1, **overrides) -> Finding:
    values = {
        'package': f'pkg-{n}',
        'version': '1.0',
        'ecosystem': 'PyPI',
        'id': f'CVE-2026-{n:04d}',
        'aliases': (f'CVE-2026-{n:04d}', f'GHSA-{n:04d}'),
        'severity': 7.5,
        'fixed': '2.0',
        'source': 'requirements.txt',
    }
    values.update(overrides)
    return Finding(**values)


class FakeRunner:
    def __init__(self, outputs=None, error=None):
        self.calls: list[list[str]] = []
        self.outputs = outputs or {}
        self.error = error

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        if self.error:
            raise self.error
        for key, output in self.outputs.items():
            if args[:2] == list(key):
                return output
        return ''


def test_decide_covers_all_four_cases():
    issue = Issue(number=7, body='old')

    assert decide(None, []) == 'none'
    assert decide(None, [finding()]) == 'create'
    assert decide(issue, [finding()]) == 'comment'
    assert decide(issue, []) == 'close'


def test_body_marks_findings_without_fix():
    body = render_body([finding(1, fixed='13.0.0'), finding(2, fixed=None)], RUN_URL)

    assert '13.0.0' in body
    assert 'no fix available' in body
    assert RUN_URL in body


def test_body_truncates_at_row_limit_and_links_run():
    findings = [finding(n) for n in range(1, 151)]

    body = render_body(findings, RUN_URL)

    rows = [line for line in body.splitlines() if line.startswith('| `pkg-')]
    assert len(rows) == ROW_LIMIT == 50
    assert '150' in body
    assert RUN_URL in body
    assert len(body) < 65536


def test_comment_counts_new_and_still_open():
    findings = [finding(1), finding(2), finding(3, fixed=None)]

    comment = render_comment(
        findings, frozenset({'CVE-2026-0001', 'CVE-2026-0002'}), RUN_URL
    )

    assert 'Still open: 2' in comment
    assert 'New since the last scan: 1' in comment
    assert 'Without a fix: 1' in comment
    assert RUN_URL in comment


def test_ids_from_body_round_trips_every_id_even_when_rows_are_truncated():
    findings = [finding(n) for n in range(1, 151)]

    assert ids_from_body(render_body(findings, RUN_URL)) == {f.id for f in findings}


def test_gh_client_reports_disabled_issues():
    error = subprocess.CalledProcessError(
        1, ['gh'], stderr="the 'o/r' repository has disabled issues"
    )
    client = GhIssueClient('o/r', runner=FakeRunner(error=error))

    with pytest.raises(RuntimeError, match='issues are disabled for o/r'):
        client.find_open()


def test_gh_client_find_open_parses_json():
    listing = json.dumps([{'number': 12, 'body': 'text'}])
    runner = FakeRunner({('issue', 'list'): listing})

    issue = GhIssueClient('o/r', runner=runner).find_open()

    assert issue == Issue(number=12, body='text')
    assert LABEL in runner.calls[0]


def test_gh_client_find_open_returns_none_for_empty_list():
    runner = FakeRunner({('issue', 'list'): '[]'})

    assert GhIssueClient('o/r', runner=runner).find_open() is None


def test_gh_client_create_ensures_label_and_returns_number_from_url():
    runner = FakeRunner({('issue', 'create'): 'https://github.com/o/r/issues/42\n'})

    number = GhIssueClient('o/r', runner=runner).create(ISSUE_TITLE, 'body')

    assert number == 42
    assert any(call[:2] == ['label', 'create'] for call in runner.calls)


def test_gh_client_close_posts_the_comment_with_the_close():
    runner = FakeRunner()

    GhIssueClient('o/r', runner=runner).close(5, 'all clear')

    assert runner.calls[-1][:3] == ['issue', 'close', '5']
    assert 'all clear' in runner.calls[-1]
