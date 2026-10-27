import json
from pathlib import Path

import pytest


OUTPUT_SCHEMAS = [
    "extraction.schema.json",
    "mapping.schema.json",
    "mapping-review.schema.json",
    "pattern-ir.schema.json",
    "rule-plan.schema.json",
    "validation-job.schema.json",
    "validation-job.v2.schema.json",
    "verdict.schema.json",
    "codeql-artifact.schema.json",
    "fast-codeql-bundle.schema.json",
]


def _assert_strict_objects(node, path="$"):
    if not isinstance(node, dict):
        return
    if node.get("type") == "object":
        assert "properties" in node, f"{path}: object schema lacks properties"
        assert node.get("additionalProperties") is False, f"{path}: additionalProperties must be false"
        properties = node["properties"]
        assert set(node.get("required", [])) == set(properties), f"{path}: every property must be required"
        for name, child in properties.items():
            _assert_strict_objects(child, f"{path}.{name}")
    if node.get("type") == "array":
        _assert_strict_objects(node.get("items"), f"{path}[]")
    for keyword in ("anyOf", "oneOf", "allOf"):
        for index, child in enumerate(node.get(keyword, [])):
            _assert_strict_objects(child, f"{path}.{keyword}[{index}]")


@pytest.mark.parametrize("filename", OUTPUT_SCHEMAS)
def test_openai_output_schema_objects_are_strict(filename):
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas" / filename).read_text(encoding="utf-8"))
    _assert_strict_objects(schema)
