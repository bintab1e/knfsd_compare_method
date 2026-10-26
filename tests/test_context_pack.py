import json
import subprocess

from compare_method.context_pack import _parse_ranges, build_context_pack


def test_parse_ranges():
    assert _parse_ranges("2-4,9,12-13") == [(2, 4), (9, 9), (12, 13)]


def test_context_pack_hashes_source_and_checks_direct_edge(tmp_path):
    source = tmp_path / "linux"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=source, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=source, check=True)
    target = source / "fs" / "nfsd"
    target.mkdir(parents=True)
    code = target / "test.c"
    code.write_text(
        "int decode(void) { return 0; }\n"
        "int entry(void) { return decode(); }\n"
        "struct ops { int (*xpo_recvfrom)(void); };\n"
        "struct ops o = { .xpo_recvfrom = entry };\n"
        "int conditional(void) {\n"
        "    if (!decode()) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=source, check=True)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=source, check=True, text=True, capture_output=True
    ).stdout.strip()
    mapping = tmp_path / "mapping.json"
    mapping.write_text(
        json.dumps(
            {
                "evidence_refs": [f"{commit}:fs/nfsd/test.c:1-2"],
                "target_code": {
                    "files": ["fs/nfsd/test.c"],
                    "functions": ["entry", "decode"],
                    "remote_entrypoints": ["entry"],
                    "call_paths": [["entry", "decode"]],
                },
            }
        ),
        encoding="utf-8",
    )
    result = build_context_pack(mapping, source, commit)
    assert result["source_entries"][0]["file"] == "fs/nfsd/test.c"
    assert result["source_entries"][0]["file_sha256"]
    assert len(result["symbols"]["entry"]) == 1
    assert len(result["symbols"]["decode"]) == 1
    assert any(
        site["match_line"] == 4
        for site in result["indirect_binding_sites"]["xpo_recvfrom"]
    )
    assert result["call_path_checks"][0]["edges"][0]["status"] == "direct_textual_call"
