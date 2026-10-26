from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .common import sha256_file, write_json


def promote(staging: Path, final: Path) -> dict:
    staging_meta = staging.with_suffix(".json")
    final_meta = final.with_suffix(".json")
    if not staging.is_file() or not staging_meta.is_file():
        raise FileNotFoundError("staging image and metadata are both required")
    if final.exists() or final_meta.exists():
        raise FileExistsError("refusing to overwrite an existing final runtime image")

    metadata = json.loads(staging_meta.read_text(encoding="utf-8"))
    actual_hash = sha256_file(staging)
    if metadata.get("sha256") != actual_hash:
        raise ValueError("staging image hash does not match its metadata")
    if metadata.get("bytes") != staging.stat().st_size:
        raise ValueError("staging image size does not match its metadata")

    final.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, final)
    metadata["output"] = str(final.resolve())
    write_json(final_meta, metadata)
    staging_meta.unlink()
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote a verified staged runtime image.")
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--final", type=Path, required=True)
    args = parser.parse_args()
    metadata = promote(args.staging.resolve(), args.final.resolve())
    print(json.dumps(metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
