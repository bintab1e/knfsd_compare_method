import json
from pathlib import Path

from compare_method.evidence_fetch import _request_url, collect_case


def _case(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "case_id": "CASE-GANESHA-CVE-2099-9999-RC01",
                "references": [
                    {"url": "https://github.com/example/repo/commit/abc", "kind": "patch_or_related", "source_record_id": "R1", "source_cell": "A1"},
                    {"url": "https://evil.invalid/private", "kind": "reference", "source_record_id": "R1", "source_cell": "B1"},
                ],
            }
        ),
        encoding="utf-8",
    )


def test_collect_case_hashes_and_reuses_evidence(tmp_path: Path) -> None:
    case = tmp_path / "case.json"
    _case(case)
    calls = []

    def fake(url, **kwargs):
        calls.append(url)
        if "evil" in url:
            raise ValueError("host_not_allowed:evil.invalid")
        return b"patch bytes\n", url, "text/x-patch"

    config = {
        "allowed_schemes": ["https"],
        "allowed_hosts": ["github.com"],
        "allowed_content_types": ["text/x-patch"],
        "max_bytes_per_reference": 1000,
        "timeout_seconds": 1,
    }
    first = collect_case(case, tmp_path / "evidence", config, fake)
    second = collect_case(case, tmp_path / "evidence", config, fake)
    assert first["counts"] == {"fetched": 1, "blocked_or_failed": 1}
    assert second["counts"] == first["counts"]
    assert calls.count("https://github.com/example/repo/commit/abc") == 1
    fetched = next(item for item in first["references"] if item["status"] == "fetched")
    assert (tmp_path / "evidence" / first["case_id"] / fetched["path"]).read_bytes() == b"patch bytes\n"


def test_failed_reference_does_not_create_payload(tmp_path: Path) -> None:
    case = tmp_path / "case.json"
    _case(case)

    def blocked(url, **kwargs):
        raise ValueError("blocked")

    config = {
        "allowed_schemes": ["https"],
        "allowed_hosts": ["github.com"],
        "allowed_content_types": ["text/plain"],
        "max_bytes_per_reference": 1000,
        "timeout_seconds": 1,
    }
    result = collect_case(case, tmp_path / "evidence", config, blocked)
    assert result["counts"]["fetched"] == 0
    assert not (tmp_path / "evidence" / result["case_id"] / "references").exists()


def test_kernel_commit_links_use_content_addressed_https_mirrors() -> None:
    assert _request_url(
        "https://git.kernel.org/stable/c/033e783709ce99662cf81f6abcad746a8da9d35f"
    ) == (
        "https://github.com/gregkh/linux/commit/"
        "033e783709ce99662cf81f6abcad746a8da9d35f.patch"
    )
    assert _request_url(
        "http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/"
        "?id=b550a32e60a4941994b437a8d662432a486235a5"
    ) == (
        "https://github.com/torvalds/linux/commit/"
        "b550a32e60a4941994b437a8d662432a486235a5.patch"
    )
