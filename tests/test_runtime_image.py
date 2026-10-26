from __future__ import annotations

import json
from pathlib import Path

from compare_method.common import sha256_file
from compare_method.runtime_image import promote


def test_promote_verified_staging_image(tmp_path: Path) -> None:
    staging = tmp_path / "staging-image.qcow2"
    staging.write_bytes(b"verified image")
    staging.with_suffix(".json").write_text(
        json.dumps(
            {
                "output": str(staging),
                "sha256": sha256_file(staging),
                "bytes": staging.stat().st_size,
            }
        ),
        encoding="utf-8",
    )
    final = tmp_path / "image.qcow2"

    metadata = promote(staging, final)

    assert final.read_bytes() == b"verified image"
    assert not staging.exists()
    assert metadata["output"] == str(final.resolve())
    assert json.loads(final.with_suffix(".json").read_text())["sha256"] == sha256_file(final)
