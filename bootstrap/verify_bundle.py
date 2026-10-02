"""Offline byte and header checks for the inert exact-head bootstrap bundle.

This verifier cannot establish signed Git ancestry, a live GitHub base,
publication authority, qualification, or a review receipt. It never imports
or executes content from the candidate HEAD.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

EXPECTED: dict[str, str | int] = {
    "schema": "bootstrap-intent/v1",
    "control_repository": "dst-red-Wire/ecommerce-1-control-plane",
    "control_default_branch": "main",
    "target_repository": "dst-red-Wire/ecommerce-1",
    "target_default_branch": "main",
    "publication_branch": "feat/controller-receipt-cutover",
    "base_sha": "29859406d056debcaab2c8fc7a353a00de987971",
    "head_sha": "b1ac8599ba9f746a7c194359e04f17a890098723",
    "tree_sha": "1424fcd7af8b626a84e533bf4eaf7e8678be8d22",
    "signer_fingerprint": "D0E9857876048A4E303B4972BA1BD2FFE663316C",
    "bundle_path": "bootstrap/source.bundle",
    "bundle_sha256": "d1ac6d0b8bcb641e9dfe39090b3039c289a733005f8f38a19b4ed592712bfadc",
    "bundle_bytes": 87538,
    "work_item_issue": 188,
    "work_item_issue_body_sha256": "7266035bab1c0df74bf4f288c9b093aecc38d129ca508dfd6a7f304cfebc9847",
    "work_package_path": "config/work-packages/M7/m7-isolated-pr-bootstrap.yaml",
    "work_package_sha256": "b9d7ca6bdd222337a5b350262037c101b79e4c0fa71b03d371346c813f1b491b",
    "environment": "ecommerce-1-bootstrap-publisher",
    "required_reviewer": "dst-red-Wire",
    "dispatch_actor": "myname37",
}
MAX_MANIFEST_BYTES = 4096
MAX_BUNDLE_BYTES = 100_000


class VerificationBlocked(ValueError):
    """The staged bundle or identity is different from the pinned proposal."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise VerificationBlocked("duplicate intent key")
        output[key] = value
    return output


def _read_file(path: Path, maximum: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > maximum
            ):
                raise VerificationBlocked(
                    "input must be a bounded single-link regular file"
                )
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise VerificationBlocked("input file unavailable") from exc
    if len(data) > maximum:
        raise VerificationBlocked("input exceeds byte limit")
    return data


def load_intent(root: Path) -> dict[str, Any]:
    raw = _read_file(root / "bootstrap" / "intent.json", MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise VerificationBlocked("invalid intent JSON") from exc
    if type(value) is not dict or set(value) != set(EXPECTED):
        raise VerificationBlocked("intent schema or key set differs from pin")
    for key, expected in EXPECTED.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            raise VerificationBlocked(f"intent {key} differs from pin")
    return value


def _validate_header(data: bytes, intent: dict[str, Any]) -> None:
    marker = data.find(b"\n\n", 0, 4096)
    if marker < 0 or data[marker + 2 : marker + 6] != b"PACK":
        raise VerificationBlocked("Git bundle header or pack magic is invalid")
    try:
        lines = data[:marker].decode("ascii").splitlines()
    except UnicodeError as exc:
        raise VerificationBlocked("Git bundle header is not ASCII") from exc
    expected_ref = f"{intent['head_sha']} refs/heads/{intent['publication_branch']}"
    if len(lines) != 3 or lines[0] != "# v2 git bundle":
        raise VerificationBlocked("Git bundle version or ref count differs from pin")
    if not lines[1].startswith(f"-{intent['base_sha']} "):
        raise VerificationBlocked("Git bundle base prerequisite differs from pin")
    if lines[2] != expected_ref:
        raise VerificationBlocked("Git bundle head ref differs from pin")


def verify_bundle(root: Path, intent: dict[str, Any]) -> dict[str, Any]:
    if intent != EXPECTED:
        raise VerificationBlocked("intent has not passed exact-pin verification")
    path = root / str(intent["bundle_path"])
    if not path.exists():
        raise VerificationBlocked("source bundle is not provisioned")
    data = _read_file(path, MAX_BUNDLE_BYTES)
    if len(data) != intent["bundle_bytes"]:
        raise VerificationBlocked("bundle byte count differs from pin")
    if hashlib.sha256(data).hexdigest() != intent["bundle_sha256"]:
        raise VerificationBlocked("bundle digest differs from pin")
    _validate_header(data, intent)
    return {
        "status": "OBSERVED_BUNDLE_ONLY",
        "bundle_sha256": intent["bundle_sha256"],
        "bundle_bytes": intent["bundle_bytes"],
        "base_sha": intent["base_sha"],
        "head_sha": intent["head_sha"],
        "work_item_issue": intent["work_item_issue"],
        "work_package_blob_sha256_verified": False,
        "head_objects_verified": False,
        "signatures_verified": False,
        "live_base_verified": False,
        "publication_authorized": False,
        "formal_preflight": False,
    }


def main() -> int:
    try:
        root = Path(__file__).resolve().parents[1]
        result = verify_bundle(root, load_intent(root))
    except VerificationBlocked as exc:
        print(f"BLOCKED_AUTHORITY: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
