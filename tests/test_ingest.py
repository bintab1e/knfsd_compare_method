from compare_method.ingest import _build_case, _group_key


def _record(cve=None, commit=None, root_cause="bounds check missing"):
    return {
        "record_id": "KNFSD:Sheet:1:R2",
        "workbook": "source.xlsx",
        "workbook_sha256": "a" * 64,
        "sheet": "Sheet",
        "excel_row": 2,
        "source_number": 1,
        "raw_fields": {"이름": cve or commit or "unknown"},
        "source_cells": {"이름": {"coordinate": "B2"}},
        "_normalized": {
            "title": cve or commit or "unknown",
            "target_implementation": "Linux KNFSD",
            "protocol_version": "NFSv4",
            "priority_raw": "높음",
            "attack_surface": "COMPOUND",
            "root_cause": root_cause,
            "affected_versions": "unknown",
            "cvss_raw": None,
            "published_or_commit_date": "2025-01-01",
        },
        "_cves": [cve] if cve else [],
        "_commits": [commit] if commit else [],
        "_references": [],
    }


def test_cve_is_primary_identifier():
    record = _record("CVE-2025-12345", "0123456789abcdef0123456789abcdef01234567")
    assert _group_key(record) == ("cve", "CVE-2025-12345")
    case = _build_case("KNFSD", _group_key(record), [record])
    assert case["case_id"] == "CASE-KNFSD-CVE-2025-12345-RC01"
    assert case["identifier"]["commit_sha"] is None


def test_multiple_root_cause_claims_are_flagged_not_blended():
    first = _record("CVE-2025-12345", root_cause="missing bounds check")
    second = _record("CVE-2025-12345", root_cause="lifetime error")
    case = _build_case("KNFSD", ("cve", "CVE-2025-12345"), [first, second])
    assert case["workflow"]["root_cause_split_status"] == "needs_review"
    assert len(case["facts"]["root_cause_claims"]) == 2


def test_unresolved_identifier_is_stable():
    record = _record()
    first = _group_key(record)
    second = _group_key(record)
    assert first == second
    assert first[0] == "unresolved"
    assert len(first[1]) == 12
