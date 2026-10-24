from conftest import FIXTURES
from security_scan.findings import (
    Finding,
    dedupe,
    parse_osv_scanner,
    parse_pip_audit,
)


def make(**overrides) -> Finding:
    values = {
        'package': 'demo',
        'version': '1.0',
        'ecosystem': 'PyPI',
        'id': 'CVE-2026-0001',
        'aliases': ('CVE-2026-0001', 'GHSA-aaaa-bbbb-cccc'),
        'severity': 5.0,
        'fixed': '2.0',
        'source': 'requirements.txt',
    }
    values.update(overrides)
    return Finding(**values)


def by_alias(findings: list[Finding], alias: str) -> Finding:
    return next(f for f in findings if alias in f.aliases)


def test_parse_osv_scanner_reads_package_version_ids_and_fix():
    findings = parse_osv_scanner(FIXTURES / 'osv_scanner.json')

    finding = by_alias(findings, 'GHSA-v9pv-5gc8-w2m6')

    assert finding.package == 'pillow'
    assert finding.version == '12.3.0'
    assert finding.ecosystem == 'PyPI'
    assert finding.id == 'CVE-2026-96639'
    assert 'GHSA-v9pv-5gc8-w2m6' in finding.aliases
    assert finding.severity == 9.8
    assert finding.fixed == '13.0.0'
    assert finding.source == 'requirements.txt'


def test_parse_osv_scanner_without_fix_gives_none():
    findings = parse_osv_scanner(FIXTURES / 'osv_scanner.json')

    finding = by_alias(findings, 'RUSTSEC-2023-0071')

    assert finding.package == 'rsa'
    assert finding.fixed is None
    assert finding.severity == 5.9
    assert finding.source == 'Cargo.lock'


def test_parse_pip_audit_reads_fix_versions():
    findings = parse_pip_audit(FIXTURES / 'pip_audit.json')

    finding = by_alias(findings, 'GHSA-22hg-r758-rrw9')

    assert finding.package == 'pillow'
    assert finding.version == '12.3.0'
    assert finding.ecosystem == 'PyPI'
    assert finding.id == 'CVE-2026-112390'
    assert finding.fixed == '13.0.0'
    assert finding.severity is None


def test_dedupe_merges_same_advisory_reported_by_both_tools():
    both = parse_osv_scanner(FIXTURES / 'osv_scanner.json') + parse_pip_audit(
        FIXTURES / 'pip_audit.json'
    )

    merged = dedupe(both)

    matches = [f for f in merged if 'CVE-2026-112393' in f.aliases]
    assert len(matches) == 1
    assert 'GHSA-332p-7hrc-92wf' in matches[0].aliases
    assert matches[0].severity == 9.2
    assert len(merged) == len(both) - 2


def test_dedupe_keeps_same_advisory_on_different_versions():
    first = make(version='1.0')
    second = make(version='1.5')

    assert len(dedupe([first, second])) == 2


def test_dedupe_orders_by_severity():
    low = make(package='low', id='CVE-1', aliases=('CVE-1',), severity=2.0)
    unknown = make(package='unknown', id='CVE-2', aliases=('CVE-2',), severity=None)
    high = make(package='high', id='CVE-3', aliases=('CVE-3',), severity=9.0)

    ordered = dedupe([low, unknown, high])

    assert [f.package for f in ordered] == ['high', 'low', 'unknown']
