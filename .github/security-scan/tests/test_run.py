from datetime import date

from conftest import FIXTURES

from security_scan.__main__ import main, run
from security_scan.issue import ISSUE_TITLE, Issue

RUN_URL = 'https://github.com/o/r/actions/runs/1'
TODAY = date(2026, 10, 24)


class FakeClient:
    def __init__(self, open_issue: Issue | None = None):
        self.open_issue = open_issue
        self.created: list[tuple[str, str]] = []
        self.updated: list[tuple[int, str]] = []
        self.comments: list[tuple[int, str]] = []
        self.closed: list[tuple[int, str]] = []

    def find_open(self):
        return self.open_issue

    def create(self, title, body):
        self.created.append((title, body))
        return 1

    def update(self, number, body):
        self.updated.append((number, body))

    def comment(self, number, text):
        self.comments.append((number, text))

    def close(self, number, text):
        self.closed.append((number, text))


OSV = FIXTURES / 'osv_scanner.json'
PIP = FIXTURES / 'pip_audit.json'


def test_no_inputs_and_no_issue_does_nothing(tmp_path):
    client = FakeClient()

    action = run(None, [], tmp_path / 'osv-scanner.toml', client, RUN_URL, TODAY)

    assert action == 'none'
    assert not (client.created or client.updated or client.comments or client.closed)


def test_findings_without_issue_creates_one(tmp_path):
    client = FakeClient()

    action = run(OSV, [PIP], tmp_path / 'osv-scanner.toml', client, RUN_URL, TODAY)

    assert action == 'create'
    title, body = client.created[0]
    assert title == ISSUE_TITLE
    assert 'pillow' in body
    assert 'no fix available' in body


def test_findings_with_issue_updates_body_and_comments(tmp_path):
    previous = '<!-- security-scan-ids: CVE-2026-96639 -->'
    client = FakeClient(Issue(number=9, body=previous))

    action = run(OSV, [], tmp_path / 'osv-scanner.toml', client, RUN_URL, TODAY)

    assert action == 'comment'
    assert client.updated[0][0] == 9
    assert 'pillow' in client.updated[0][1]
    assert 'Still open: 1' in client.comments[0][1]
    assert not client.created


def test_empty_result_closes_open_issue(tmp_path):
    client = FakeClient(Issue(number=9, body='old'))

    action = run(None, [], tmp_path / 'osv-scanner.toml', client, RUN_URL, TODAY)

    assert action == 'close'
    assert client.closed[0][0] == 9
    assert 'No open vulnerabilities' in client.closed[0][1]


def test_ignored_finding_does_not_open_an_issue(tmp_path):
    toml = tmp_path / 'osv-scanner.toml'
    toml.write_text(
        ''.join(
            f'[[IgnoredVulns]]\nid = "{advisory}"\nreason = "accepted"\n\n'
            for advisory in ('CVE-2026-112393', 'CVE-2026-112398', 'CVE-2026-112390')
        )
    )
    client = FakeClient()

    action = run(None, [PIP], toml, client, RUN_URL, TODAY)

    assert action == 'none'
    assert not client.created


def test_unparsable_pip_audit_json_is_exit_code_2(tmp_path, capsys):
    broken = tmp_path / 'pip-audit.json'
    broken.write_text('not json')

    code = main(['--repo', 'o/r', '--pip-audit-json', str(broken)])

    assert code == 2
    assert 'pip-audit.json' in capsys.readouterr().err


def test_missing_osv_json_is_exit_code_2(tmp_path, capsys):
    code = main(['--repo', 'o/r', '--osv-json', str(tmp_path / 'absent.json')])

    assert code == 2
    assert 'absent.json' in capsys.readouterr().err
