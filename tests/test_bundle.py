"""Tamper checks for the inert bootstrap transfer artifact."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bootstrap"))
from verify_bundle import (
    EXPECTED,
    VerificationBlocked,
    _validate_header,
    load_intent,
    verify_bundle,
)


class BundleTests(unittest.TestCase):
    def test_public_checkout_has_no_source_bundle(self) -> None:
        self.assertFalse((ROOT / "bootstrap" / "source.bundle").exists())

    def test_missing_source_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bootstrap").mkdir()
            with self.assertRaisesRegex(
                VerificationBlocked, "source bundle is not provisioned"
            ):
                verify_bundle(root, EXPECTED)

    def test_changed_bundle_byte_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bootstrap").mkdir()
            data = b"x" * int(EXPECTED["bundle_bytes"])
            (root / "bootstrap" / "source.bundle").write_bytes(data)
            with self.assertRaisesRegex(VerificationBlocked, "digest"):
                verify_bundle(root, EXPECTED)

    def test_extra_ref_is_refused(self) -> None:
        data = (
            b"# v2 git bundle\n"
            + f"-{EXPECTED['base_sha']} base\n".encode("ascii")
            + (
                f"{EXPECTED['head_sha']} "
                f"refs/heads/{EXPECTED['publication_branch']}\n"
            ).encode("ascii")
            + b"0" * 40
            + b" refs/heads/other\n\nPACK"
        )
        with self.assertRaisesRegex(VerificationBlocked, "ref count"):
            _validate_header(data, EXPECTED)

    def test_intent_rejects_extra_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bootstrap").mkdir()
            (root / "bootstrap" / "intent.json").write_text(
                json.dumps({**EXPECTED, "extra": "untrusted"}), encoding="utf-8"
            )
            with self.assertRaises(VerificationBlocked):
                load_intent(root)
            valid = json.dumps(EXPECTED)
            duplicated = valid[:-1] + ', "base_sha": "other"}'
            (root / "bootstrap" / "intent.json").write_text(
                duplicated, encoding="utf-8"
            )
            with self.assertRaises(VerificationBlocked):
                load_intent(root)


if __name__ == "__main__":
    unittest.main()
