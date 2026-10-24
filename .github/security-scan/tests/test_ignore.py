from datetime import date

from security_scan.findings import Finding
from security_scan.ignore import apply_ignores, load_ignored_ids

TODAY = date(2026, 10, 24)


def finding(**overrides) -> Finding:
    values = {
        'package': 'zod',
        'version': '3.25.76',
        'ecosystem': 'npm',
        'id': 'CVE-2023-54404',
        'aliases': ('CVE-2023-54404', 'GHSA-mrhx-c7xc-m3w5'),
        'severity': 8.2,
        'fixed': '4.6.6',
        'source': 'package-lock.json',
    }
    values.update(overrides)
    return Finding(**values)


def write(tmp_path, text: str):
    path = tmp_path / 'osv-scanner.toml'
    path.write_text(text)
    return path


def test_missing_file_ignores_nothing(tmp_path):
    assert load_ignored_ids(tmp_path / 'absent.toml', TODAY) == frozenset()


def test_entry_without_expiry_is_ignored(tmp_path):
    path = write(
        tmp_path, '[[IgnoredVulns]]\nid = "GHSA-mrhx-c7xc-m3w5"\nreason = "accepted"\n'
    )

    assert load_ignored_ids(path, TODAY) == {'GHSA-mrhx-c7xc-m3w5'}


def test_entry_with_future_expiry_is_ignored(tmp_path):
    path = write(
        tmp_path,
        '[[IgnoredVulns]]\nid = "GHSA-mrhx-c7xc-m3w5"\nignoreUntil = 2026-12-31\n',
    )

    assert load_ignored_ids(path, TODAY) == {'GHSA-mrhx-c7xc-m3w5'}


def test_entry_with_expired_date_resurfaces_finding(tmp_path):
    path = write(
        tmp_path,
        '[[IgnoredVulns]]\nid = "GHSA-mrhx-c7xc-m3w5"\nignoreUntil = 2026-10-23\n',
    )
    ignored = load_ignored_ids(path, TODAY)

    assert ignored == frozenset()
    assert apply_ignores([finding()], ignored) == [finding()]


def test_entry_expiring_today_is_still_ignored(tmp_path):
    path = write(
        tmp_path,
        '[[IgnoredVulns]]\nid = "GHSA-mrhx-c7xc-m3w5"\nignoreUntil = 2026-10-24\n',
    )

    assert load_ignored_ids(path, TODAY) == {'GHSA-mrhx-c7xc-m3w5'}


def test_alias_match_drops_finding():
    # the toml lists the GHSA id while the finding's own id is the CVE
    kept = apply_ignores(
        [finding(), finding(package='other', aliases=('CVE-1',), id='CVE-1')],
        frozenset({'GHSA-mrhx-c7xc-m3w5'}),
    )

    assert [f.package for f in kept] == ['other']
