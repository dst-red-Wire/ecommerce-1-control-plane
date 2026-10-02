"""Bounded PAT publisher tests; no network, credential, or remote mutation."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bootstrap"))

import pat_publisher
from actions_publisher import PublicationBlocked
from verify_bundle import EXPECTED

TOKEN = "github_pat_" + "x" * 48
PUSH = {
    "kind": "PUSH_REF_NON_FORCE",
    "repository": "dst-red-Wire/ecommerce-1",
    "ref": "refs/heads/feat/controller-receipt-cutover",
    "new_sha": EXPECTED["head_sha"],
    "force": False,
}
CREATE = {
    "kind": "CREATE_PR",
    "repository": "dst-red-Wire/ecommerce-1",
    "head": "dst-red-Wire:feat/controller-receipt-cutover",
    "base": "main",
    "title": "M7: bootstrap independent PR qualification",
    "body": "exact body",
    "draft": True,
}
NOOP = {"kind": "NOOP"}


def plan(action: dict, number: int | None = None) -> dict:
    return {"action": action, "pr_number": number}


class BoundedPublisherTests(unittest.TestCase):
    def _run(self) -> dict:
        return pat_publisher.publish_bounded(
            ROOT,
            context={},
            approved_control_sha="a" * 40,
            base_objects=ROOT,
            trusted_gnupg_home=ROOT,
            token=TOKEN,
        )

    def test_push_then_create_each_has_fresh_plan_and_exact_readback(self) -> None:
        plans = [
            plan(PUSH), plan(PUSH), plan(CREATE),  # push, recheck, readback
            plan(CREATE), plan(CREATE), plan(NOOP, 189),  # PR
            plan(NOOP, 189),  # final independent preflight and readback
        ]
        with (
            mock.patch.object(
                pat_publisher, "_preflight", return_value=dict(EXPECTED)
            ) as preflight,
            mock.patch.object(pat_publisher, "_plan", side_effect=plans) as planner,
            mock.patch.object(pat_publisher, "_verify_token_owner") as owner,
            mock.patch.object(
                pat_publisher, "verify_live_target_base"
            ) as target,
            mock.patch.object(
                pat_publisher, "verify_live_work_item"
            ) as issue,
            mock.patch.object(pat_publisher, "_push_exact_head") as push,
            mock.patch.object(pat_publisher, "_write_pr") as write_pr,
        ):
            push.side_effect = lambda *args, **kwargs: kwargs["recheck"]()
            result = self._run()
        self.assertEqual(
            result["actions"], ["PUSH_REF_NON_FORCE", "CREATE_PR"]
        )
        self.assertEqual(result["status"], "EXACT_BOOTSTRAP_PR_OBSERVED")
        self.assertFalse(result["head_executed"])
        self.assertFalse(result["formal_preflight"])
        self.assertFalse(result["full_qualification"])
        self.assertEqual(preflight.call_count, 3)
        self.assertEqual(planner.call_count, 7)
        self.assertEqual(owner.call_count, 2)
        self.assertEqual(target.call_count, 2)
        self.assertEqual(issue.call_count, 2)
        push.assert_called_once()
        write_pr.assert_called_once_with(CREATE, TOKEN)

    def test_live_drift_blocks_before_branch_push(self) -> None:
        with (
            mock.patch.object(
                pat_publisher, "_preflight", return_value=dict(EXPECTED)
            ),
            mock.patch.object(
                pat_publisher, "_plan", side_effect=[plan(PUSH), plan(NOOP, 189)]
            ),
            mock.patch.object(pat_publisher, "_verify_token_owner"),
            mock.patch.object(pat_publisher, "verify_live_target_base"),
            mock.patch.object(pat_publisher, "verify_live_work_item"),
            mock.patch.object(pat_publisher, "_push_exact_head") as push,
        ):
            push.side_effect = lambda *args, **kwargs: kwargs["recheck"]()
            with self.assertRaisesRegex(
                PublicationBlocked, "changed before write"
            ):
                self._run()
        push.assert_called_once()  # The fake only invoked the pre-write recheck.

    def test_post_write_mismatch_blocks_success(self) -> None:
        with (
            mock.patch.object(
                pat_publisher, "_preflight", return_value=dict(EXPECTED)
            ),
            mock.patch.object(
                pat_publisher, "_plan",
                side_effect=[plan(CREATE), plan(CREATE), plan(CREATE)]
            ),
            mock.patch.object(pat_publisher, "_verify_token_owner"),
            mock.patch.object(pat_publisher, "verify_live_target_base"),
            mock.patch.object(pat_publisher, "verify_live_work_item"),
            mock.patch.object(pat_publisher, "_write_pr") as write_pr,
            self.assertRaisesRegex(PublicationBlocked, "post-write"),
        ):
            self._run()
        write_pr.assert_called_once()

    def test_invalid_token_blocks_before_preflight(self) -> None:
        with (
            mock.patch.object(pat_publisher, "_preflight") as preflight,
            self.assertRaisesRegex(PublicationBlocked, "PAT"),
        ):
            pat_publisher.publish_bounded(
                ROOT,
                context={},
                approved_control_sha="a" * 40,
                base_objects=ROOT,
                trusted_gnupg_home=ROOT,
                token="ghp_" + "invalid" * 4,
            )
        preflight.assert_not_called()

    def test_push_imports_bundle_without_checkout_or_token_in_arguments(self) -> None:
        source = b"synthetic signed bundle bytes"
        intent = dict(EXPECTED)
        intent["bundle_bytes"] = len(source)
        intent["bundle_sha256"] = hashlib.sha256(source).hexdigest()
        git_calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_git(
            repo: Path,
            args: list[str],
            *,
            work: Path,
            env: dict[str, str],
            label: str,
        ) -> bytes:
            git_calls.append((args, dict(env)))
            if args[0] == "bundle" and args[1] == "unbundle":
                return (
                    f"{intent['head_sha']} refs/heads/"
                    f"{intent['publication_branch']}\n"
                ).encode("ascii")
            if args[0] == "cat-file":
                return b"commit\n"
            return b""

        with (
            mock.patch.object(
                pat_publisher, "_read_file", return_value=source
            ),
            mock.patch.object(
                pat_publisher, "_environment", return_value={"PATH": "/usr/bin"}
            ),
            mock.patch.object(pat_publisher, "_run"),
            mock.patch.object(pat_publisher, "_git", side_effect=fake_git),
        ):
            recheck = mock.Mock()
            pat_publisher._push_exact_head(
                ROOT,
                intent,
                base_objects=ROOT,
                trusted_gnupg_home=ROOT,
                token=TOKEN,
                recheck=recheck,
            )
        recheck.assert_called_once()
        self.assertEqual(len(git_calls), 4)
        for args, env in git_calls[:-1]:
            self.assertNotIn(TOKEN, repr(args))
            self.assertNotIn("BOOTSTRAP_TARGET_PAT", env)
        push_args, push_env = git_calls[-1]
        self.assertIn("push", push_args)
        self.assertIn("--no-verify", push_args)
        self.assertNotIn("--force", push_args)
        self.assertNotIn("--force-with-lease", push_args)
        self.assertEqual(push_env["BOOTSTRAP_TARGET_PAT"], TOKEN)
        self.assertNotIn(TOKEN, repr(push_args))
        self.assertNotIn("checkout", repr(git_calls))
        self.assertNotIn("HEAD", repr(git_calls))

    def test_request_rejects_other_repository_before_network(self) -> None:
        with (
            mock.patch.object(
                pat_publisher.urllib.request, "build_opener"
            ) as opener,
            self.assertRaisesRegex(PublicationBlocked, "outside the target"),
        ):
            pat_publisher._request_json("repos/other/repo/pulls")
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
