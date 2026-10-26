import json
from pathlib import Path

from compare_method.round_result import build_round_result


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_complete_round_aggregates_verdicts(tmp_path: Path) -> None:
    candidates = tmp_path / "candidates"
    verdicts = tmp_path / "verdicts"
    validation = tmp_path / "validation"
    _write(candidates / "CANDIDATE-ONE.json", {"candidate_id": "CANDIDATE-ONE"})
    _write(
        verdicts / "CANDIDATE-ONE.json",
        {"candidate_id": "CANDIDATE-ONE", "final_label": "confirmed_fp"},
    )
    for sanitizer in ("kasan", "kcsan"):
        _write(
            validation / sanitizer / "result.json",
            {"results": [{"candidate_id": "CANDIDATE-ONE", "terminal_label": "no_signal"}]},
        )

    result = build_round_result(
        "PATTERN-ONE", 1, candidates, validation, verdicts, tmp_path / "round.json"
    )

    assert result["status"] == "complete"
    assert result["label_counts"] == {"confirmed_fp": 1}
    assert result["ruleset_action"] == "refine_before_next_round"


def test_empty_candidate_round_is_complete_but_not_promotion_ready(tmp_path: Path) -> None:
    candidates = tmp_path / "candidates"
    verdicts = tmp_path / "verdicts"
    candidates.mkdir()
    verdicts.mkdir()

    result = build_round_result(
        "PATTERN-ONE", 2, candidates, tmp_path / "validation", verdicts,
        tmp_path / "round.json"
    )

    assert result["status"] == "complete"
    assert result["candidate_count"] == 0
    assert result["promotion_ready"] is False
    assert result["ruleset_action"] == "run_regression_and_holdout_before_promotion"
