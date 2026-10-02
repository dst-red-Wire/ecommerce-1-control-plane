"""Synthetic Git-object tests for the inactive bootstrap inspector."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bootstrap"))

from inspect_objects import (
    ObjectInspectionBlocked,
    _inspect_bundle_objects,
    inspect_objects,
)
from verify_bundle import VerificationBlocked


def _command(
    argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> str:
    result = subprocess.run(
        argv, cwd=cwd, env=env, check=True, capture_output=True, text=True, timeout=30
    )
    return result.stdout.strip()


class ObjectInspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.keys_directory = tempfile.TemporaryDirectory()
        cls.keys_root = Path(cls.keys_directory.name)
        cls.signing_home = cls.keys_root / "signing"
        cls.trusted_home = cls.keys_root / "trusted"
        cls.signing_home.mkdir(mode=0o700)
        cls.trusted_home.mkdir(mode=0o700)
        _command(
            [
                "/usr/bin/gpg",
                "--homedir",
                str(cls.signing_home),
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Fixture Signer <fixture@example.invalid>",
                "ed25519",
                "sign",
                "0",
            ]
        )
        listing = _command(
            [
                "/usr/bin/gpg",
                "--homedir",
                str(cls.signing_home),
                "--batch",
                "--with-colons",
                "--list-keys",
            ]
        )
        cls.fingerprint = next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        )
        public_key = subprocess.run(
            [
                "/usr/bin/gpg",
                "--homedir",
                str(cls.signing_home),
                "--batch",
                "--export",
                cls.fingerprint,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        subprocess.run(
            ["/usr/bin/gpg", "--homedir", str(cls.trusted_home), "--batch", "--import"],
            input=public_key,
            check=True,
            capture_output=True,
            timeout=30,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.keys_directory.cleanup()

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.bundle = self.root / "source.bundle"
        self.sentinel = self.root / "candidate-executed"
        self.env = {
            **os.environ,
            "GNUPGHOME": str(self.signing_home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "LC_ALL": "C",
        }
        self._git("init", "-q", "-b", "main", str(self.repo), cwd=self.root)
        self._git("config", "user.name", "Fixture Signer")
        self._git("config", "user.email", "fixture@example.invalid")
        self._git("config", "user.signingkey", self.fingerprint)
        self._git("config", "commit.gpgsign", "true")
        (self.repo / "base.txt").write_text("fixed base\n", encoding="utf-8")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "base")
        self.base = self._git("rev-parse", "HEAD")
        self._git("checkout", "-q", "-b", "feature")
        (self.repo / "candidate.txt").write_text("candidate data\n", encoding="utf-8")
        (self.repo / "Makefile").write_text(
            f"all:\n\t@touch {self.sentinel}\n", encoding="utf-8"
        )
        repoctl = self.repo / "repoctl"
        repoctl.write_text(f"#!/bin/sh\ntouch {self.sentinel}\n", encoding="utf-8")
        repoctl.chmod(0o755)
        hooks = self.repo / ".git" / "hooks"
        (hooks / "post-fetch").write_text(
            f"#!/bin/sh\ntouch {self.sentinel}\n", encoding="utf-8"
        )
        (hooks / "post-fetch").chmod(0o755)
        (hooks / "post-checkout").write_text(
            f"#!/bin/sh\ntouch {self.sentinel}\n", encoding="utf-8"
        )
        (hooks / "post-checkout").chmod(0o755)
        self._git("add", "candidate.txt", "Makefile", "repoctl")
        self._git("commit", "-q", "-m", "candidate")
        self._bundle()

    def _git(self, *args: str, cwd: Path | None = None) -> str:
        return _command(["/usr/bin/git", *args], cwd=cwd or self.repo, env=self.env)

    def _bundle(self) -> None:
        self.head = self._git("rev-parse", "HEAD")
        self.tree = self._git("rev-parse", "HEAD^{tree}")
        self._git("bundle", "create", str(self.bundle), "feature", f"^{self.base}")
        data = self.bundle.read_bytes()
        self.intent = {
            "base_sha": self.base,
            "head_sha": self.head,
            "tree_sha": self.tree,
            "signer_fingerprint": self.fingerprint,
            "publication_branch": "feature",
            "bundle_bytes": len(data),
            "bundle_sha256": hashlib.sha256(data).hexdigest(),
        }

    def _inspect(
        self,
        *,
        intent: dict | None = None,
        bundle: Path | None = None,
        base_objects: Path | None = None,
    ) -> dict:
        return _inspect_bundle_objects(
            bundle or self.bundle,
            intent or self.intent,
            base_objects or (self.repo / ".git" / "objects"),
            self.trusted_home,
        )

    def test_signed_ancestry_and_objects_are_observed_only(self) -> None:
        result = self._inspect()
        self.assertEqual(result["status"], "OBSERVED_OBJECTS_ONLY")
        self.assertEqual(result["introduced_commits_verified"], 1)
        self.assertTrue(result["head_objects_verified"])
        self.assertTrue(result["introduced_signatures_verified"])
        self.assertTrue(result["base_ancestry_verified"])
        self.assertFalse(result["live_base_verified"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["formal_preflight"])
        self.assertFalse(self.sentinel.exists())

    def test_work_package_blob_is_pinned_without_checkout(self) -> None:
        data = (self.repo / "candidate.txt").read_bytes()
        intent = {
            **self.intent,
            "work_item_issue": 188,
            "work_package_path": "candidate.txt",
            "work_package_sha256": hashlib.sha256(data).hexdigest(),
        }
        result = self._inspect(intent=intent)
        self.assertEqual(result["work_item_issue"], 188)
        self.assertTrue(result["work_package_blob_sha256_verified"])
        self.assertFalse(self.sentinel.exists())

    def test_work_package_blob_digest_tamper_is_refused(self) -> None:
        intent = {
            **self.intent,
            "work_item_issue": 188,
            "work_package_path": "candidate.txt",
            "work_package_sha256": "0" * 64,
        }
        with self.assertRaisesRegex(ObjectInspectionBlocked, "work package blob digest"):
            self._inspect(intent=intent)
        self.assertFalse(self.sentinel.exists())

    def test_incomplete_or_invalid_work_package_pin_is_refused(self) -> None:
        with self.assertRaisesRegex(ObjectInspectionBlocked, "incomplete"):
            self._inspect(intent={**self.intent, "work_item_issue": 188})
        with self.assertRaisesRegex(ObjectInspectionBlocked, "issue pin"):
            self._inspect(
                intent={
                    **self.intent,
                    "work_item_issue": True,
                    "work_package_path": "candidate.txt",
                    "work_package_sha256": "0" * 64,
                }
            )

    def test_missing_prerequisite_is_refused(self) -> None:
        empty = self.root / "empty.git"
        self._git("init", "--bare", "-q", str(empty), cwd=self.root)
        with self.assertRaisesRegex(ObjectInspectionBlocked, "base object"):
            self._inspect(base_objects=empty / "objects")
        self.assertFalse(self.sentinel.exists())

    def test_unsigned_introduced_commit_is_refused(self) -> None:
        (self.repo / "unsigned.txt").write_text("unsigned\n", encoding="utf-8")
        self._git("add", "unsigned.txt")
        self._git("commit", "-q", "--no-gpg-sign", "-m", "unsigned")
        self._bundle()
        with self.assertRaisesRegex(ObjectInspectionBlocked, "signature"):
            self._inspect()

    def test_incorrect_signer_is_refused(self) -> None:
        intent = {**self.intent, "signer_fingerprint": "0" * 40}
        with self.assertRaisesRegex(ObjectInspectionBlocked, "fingerprint"):
            self._inspect(intent=intent)

    def test_wrong_head_tree_is_refused(self) -> None:
        intent = {**self.intent, "tree_sha": "0" * 40}
        with self.assertRaisesRegex(ObjectInspectionBlocked, "head tree"):
            self._inspect(intent=intent)

    def test_bundle_mutation_is_refused_before_git_reads_it(self) -> None:
        data = bytearray(self.bundle.read_bytes())
        data[-1] ^= 1
        self.bundle.write_bytes(data)
        with self.assertRaisesRegex(ObjectInspectionBlocked, "digest"):
            self._inspect()

    def test_git_reads_private_copy_after_original_changes(self) -> None:
        from inspect_objects import _read_file as original_read

        def mutate_after_read(path: Path, maximum: int) -> bytes:
            data = original_read(path, maximum)
            path.write_bytes(b"changed after byte verification")
            return data

        with mock.patch("inspect_objects._read_file", side_effect=mutate_after_read):
            result = self._inspect()
        self.assertEqual(result["status"], "OBSERVED_OBJECTS_ONLY")
        self.assertFalse(self.sentinel.exists())

    def test_extra_ref_in_header_is_refused(self) -> None:
        data = self.bundle.read_bytes()
        marker = data.index(b"\n\n")
        changed = (
            data[:marker] + b"\n" + b"0" * 40 + b" refs/heads/extra" + data[marker:]
        )
        self.bundle.write_bytes(changed)
        intent = {
            **self.intent,
            "bundle_bytes": len(changed),
            "bundle_sha256": hashlib.sha256(changed).hexdigest(),
        }
        with self.assertRaisesRegex(VerificationBlocked, "ref count"):
            self._inspect(intent=intent)

    def test_nonancestor_prerequisite_is_refused(self) -> None:
        self._git("checkout", "-q", "main")
        (self.repo / "other.txt").write_text("other branch\n", encoding="utf-8")
        self._git("add", "other.txt")
        self._git("commit", "-q", "-m", "other")
        other = self._git("rev-parse", "HEAD")
        data = self.bundle.read_bytes()
        self.assertIn(("-" + self.base).encode("ascii"), data[:4096])
        changed = data.replace(
            ("-" + self.base).encode("ascii"),
            ("-" + other).encode("ascii"),
            1,
        )
        self.bundle.write_bytes(changed)
        intent = {
            **self.intent,
            "base_sha": other,
            "bundle_bytes": len(changed),
            "bundle_sha256": hashlib.sha256(changed).hexdigest(),
        }
        with self.assertRaisesRegex(ObjectInspectionBlocked, "base ancestry"):
            self._inspect(intent=intent)

    def test_git_environment_and_candidate_hooks_are_not_used(self) -> None:
        poisoned = self.root / "poisoned-config"
        poisoned.write_text(
            f"[core]\n\thooksPath = {self.repo / '.git' / 'hooks'}\n",
            encoding="utf-8",
        )
        original = dict(os.environ)
        self.addCleanup(lambda: os.environ.clear() or os.environ.update(original))
        os.environ["GIT_CONFIG_GLOBAL"] = str(poisoned)
        os.environ["GIT_EXEC_PATH"] = str(self.repo)
        os.environ["GIT_TEMPLATE_DIR"] = str(self.repo / ".git" / "hooks")
        os.environ["GIT_CONFIG_COUNT"] = "1"
        os.environ["GIT_CONFIG_KEY_0"] = "core.hooksPath"
        os.environ["GIT_CONFIG_VALUE_0"] = str(self.repo / ".git" / "hooks")
        self.assertEqual(self._inspect()["status"], "OBSERVED_OBJECTS_ONLY")
        self.assertFalse(self.sentinel.exists())

    def test_public_entrypoint_rejects_unpinned_synthetic_intent(self) -> None:
        root = self.root / "control"
        (root / "bootstrap").mkdir(parents=True)
        (root / "bootstrap" / "intent.json").write_text(
            json.dumps(self.intent), encoding="utf-8"
        )
        with self.assertRaisesRegex(VerificationBlocked, "intent schema"):
            inspect_objects(
                root,
                base_objects=self.repo / ".git" / "objects",
                trusted_gnupg_home=self.trusted_home,
            )


if __name__ == "__main__":
    unittest.main()
