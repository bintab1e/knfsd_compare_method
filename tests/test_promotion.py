from compare_method.promotion import decide_promotion


def _evaluation(version: int, *, tp=(), fp=(), val=(1, 1), hold=(0, 0), candidates=10, complete=True):
    records = [
        *({"candidate_id": item, "final_label": "confirmed_tp"} for item in tp),
        *({"candidate_id": item, "final_label": "confirmed_fp"} for item in fp),
        {"candidate_id": "unknown", "final_label": "no_signal_after_100"},
    ]
    return {
        "pattern_id": "PATTERN-TEST-01",
        "rule_version": version,
        "complete": complete,
        "candidate_count": candidates,
        "runtime_seconds": 10.0,
        "partitions": {
            "development": {"records": records},
            "validation": {
                "records": [],
                "known_positive_ids": [f"v{i}" for i in range(val[1])],
                "detected_known_positive_ids": [f"v{i}" for i in range(val[0])],
            },
            "sealed_holdout": {
                "records": [],
                "known_positive_ids": [f"h{i}" for i in range(hold[1])],
                "detected_known_positive_ids": [f"h{i}" for i in range(hold[0])],
            },
        },
    }


def _policies():
    return (
        {"max_runtime_growth": 2.0},
        {
            "minimum_adjudicated_samples": 30,
            "candidate_flood_limit": None,
            "no_improvement_rounds_before_quarantine": 2,
            "protect_if": ["preserves_unique_known_tp"],
        },
    )


def test_promotes_when_tp_is_preserved_and_fp_falls() -> None:
    promotion, circuit = _policies()
    result = decide_promotion(
        _evaluation(1, tp=("tp1",), fp=("fp1", "fp2")),
        _evaluation(2, tp=("tp1",), fp=("fp1",)),
        promotion,
        circuit,
        milestone=False,
        input_hashes={name: "a" * 64 for name in ("baseline", "candidate", "promotion_policy", "circuit_breaker_policy")},
    )
    assert result["decision"] == "promote"


def test_no_signal_is_not_counted_as_false_positive() -> None:
    promotion, circuit = _policies()
    result = decide_promotion(
        _evaluation(1, tp=("tp1",)),
        _evaluation(2, tp=("tp1", "tp2")),
        promotion,
        circuit,
        milestone=False,
        input_hashes={name: "a" * 64 for name in ("baseline", "candidate", "promotion_policy", "circuit_breaker_policy")},
    )
    assert result["metrics"]["candidate"]["confirmed_fp"] == 0
    assert result["decision"] == "promote"


def test_milestone_requires_unseen_holdout_detection() -> None:
    promotion, circuit = _policies()
    result = decide_promotion(
        _evaluation(1, tp=("tp1",), hold=(0, 2)),
        _evaluation(2, tp=("tp1", "tp2"), hold=(0, 2)),
        promotion,
        circuit,
        milestone=True,
        input_hashes={name: "a" * 64 for name in ("baseline", "candidate", "promotion_policy", "circuit_breaker_policy")},
    )
    assert result["gates"]["sealed_holdout_passed"] is False
    assert result["decision"] == "keep_baseline"
