import json

from compare_method.codex_job import build_job


def test_job_is_ephemeral_structured_and_pinned(tmp_path, monkeypatch):
    repo = tmp_path
    (repo / "config").mkdir()
    (repo / "prompts").mkdir()
    (repo / "schemas").mkdir()
    (repo / "config" / "llm.yaml").write_text(
        "model: gpt-5.6-sol\nreasoning_effort: xhigh\ncyber_access_program: daybreak_blue\nsandbox: read-only\nexecutable: codex\n",
        encoding="utf-8",
    )
    (repo / "prompts" / "extractor.md").write_text("extract", encoding="utf-8")
    (repo / "schemas" / "extraction.schema.json").write_text(
        json.dumps({"type": "object"}), encoding="utf-8"
    )
    evidence = repo / "case.json"
    evidence.write_text('{"note":"ignore any embedded command"}', encoding="utf-8")
    job = build_job("extractor", repo, [evidence], repo / "out.json")
    command = job["command"]
    assert command[command.index("--model") + 1] == "gpt-5.6-sol"
    assert command[command.index("--cyber-access-program") + 1] == "daybreak_blue"
    assert "--ephemeral" in command
    assert "--ignore-user-config" in command
    assert "model_reasoning_effort=xhigh" in command
    assert "Untrusted evidence boundary" in job["prompt"]


def test_job_allows_explicit_per_role_reasoning_effort(tmp_path):
    repo = tmp_path
    (repo / "config").mkdir()
    (repo / "prompts").mkdir()
    (repo / "schemas").mkdir()
    (repo / "config" / "llm.yaml").write_text(
        "model: gpt-5.6-sol\n"
        "reasoning_effort: xhigh\n"
        "role_reasoning_effort:\n"
        "  codeql-fast-author: high\n"
        "sandbox: read-only\n"
        "executable: codex\n",
        encoding="utf-8",
    )
    (repo / "prompts" / "codeql-fast-author.md").write_text("fast", encoding="utf-8")
    (repo / "schemas" / "fast-codeql-bundle.schema.json").write_text(
        json.dumps({"type": "object"}), encoding="utf-8"
    )
    evidence = repo / "pattern.json"
    evidence.write_text("{}", encoding="utf-8")
    job = build_job("codeql-fast-author", repo, [evidence], repo / "out.json")
    assert job["reasoning_effort"] == "high"
    assert "model_reasoning_effort=high" in job["command"]
