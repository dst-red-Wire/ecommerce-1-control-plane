"""Security-relevant tests for the inactive Actions publication adapter."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bootstrap"))

from actions_publisher import (
    PublicationBlocked,
    observe_publication,
    read_public_github_json,
    validate_actions_context,
    verify_live_target_base,
    verify_live_work_item,
)

MARKER = (
    "<!-- ecommerce-work-item:v1 "
    + json.dumps(
        {
            "category": "work-item",
            "milestone": "M7",
            "tracker_issue": 20,
            "work_package_id": "m7-isolated-pr-bootstrap",
            "work_package_path": (
                "config/work-packages/M7/m7-isolated-pr-bootstrap.yaml"
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    + " -->"
)
TEST_ISSUE_BODY = MARKER + "\n\nTest body.\n"


INTENT = {
    "control_repository": "dst-red-Wire/ecommerce-1-control-plane",
    "control_default_branch": "main",
    "target_repository": "dst-red-Wire/ecommerce-1",
    "target_default_branch": "main",
    "dispatch_actor": "myname37",
    "base_sha": "1" * 40,
    "head_sha": "2" * 40,
    "tree_sha": "3" * 40,
    "bundle_sha256": "4" * 64,
    "work_item_issue": 188,
    "work_item_issue_body_sha256": hashlib.sha256(
        TEST_ISSUE_BODY.encode("utf-8")
    ).hexdigest(),
    "work_package_path": "config/work-packages/M7/m7-isolated-pr-bootstrap.yaml",
    "work_package_sha256": "5" * 64,
}
APPROVED_SHA = "a" * 40
CONTEXT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REPOSITORY": INTENT["control_repository"],
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_REF_PROTECTED": "true",
    "GITHUB_SHA": APPROVED_SHA,
    "GITHUB_WORKFLOW_SHA": APPROVED_SHA,
    "GITHUB_ACTOR": "myname37",
    "GITHUB_TRIGGERING_ACTOR": "myname37",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_WORKFLOW_REF": (
        "dst-red-Wire/ecommerce-1-control-plane/"
        ".github/workflows/bootstrap-publisher.yml@refs/heads/main"
    ),
}
OBJECTS = {
    "status": "OBSERVED_OBJECTS_ONLY",
    "base_sha": INTENT["base_sha"],
    "head_sha": INTENT["head_sha"],
    "tree_sha": INTENT["tree_sha"],
    "bundle_sha256": INTENT["bundle_sha256"],
    "head_objects_verified": True,
    "introduced_signatures_verified": True,
    "base_ancestry_verified": True,
    "work_package_blob_sha256_verified": True,
}


def public_api(path: str) -> dict:
    if path == "repos/dst-red-Wire/ecommerce-1":
        return {
            "full_name": "dst-red-Wire/ecommerce-1",
            "default_branch": "main",
            "private": False,
        }
    if path == "repos/dst-red-Wire/ecommerce-1/git/ref/heads/main":
        return {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": INTENT["base_sha"]},
        }
    if path == "repos/dst-red-Wire/ecommerce-1/issues/188":
        return {"number": 188, "state": "open", "body": TEST_ISSUE_BODY}
    if path == "repos/dst-red-Wire/ecommerce-1/issues/20":
        return {"number": 20, "state": "open", "body": "M7 tracker"}
    raise AssertionError(f"unexpected API path: {path}")


class ActionsPublisherTests(unittest.TestCase):
    def test_actions_context_requires_exact_protected_dispatch_identity(self) -> None:
        result = validate_actions_context(
            CONTEXT, INTENT, approved_control_sha=APPROVED_SHA
        )
        self.assertEqual(result["control_sha"], APPROVED_SHA)
        for key, changed in (
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REPOSITORY", "attacker/repo"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF_PROTECTED", "false"),
            ("GITHUB_SHA", "b" * 40),
            ("GITHUB_WORKFLOW_SHA", "b" * 40),
            ("GITHUB_ACTOR", "dst-red-Wire"),
            ("GITHUB_TRIGGERING_ACTOR", "dst-red-Wire"),
            ("RUNNER_ENVIRONMENT", "self-hosted"),
            ("GITHUB_WORKFLOW_REF", "attacker/workflow@main"),
        ):
            with self.subTest(key=key), self.assertRaises(PublicationBlocked):
                validate_actions_context(
                    {**CONTEXT, key: changed},
                    INTENT,
                    approved_control_sha=APPROVED_SHA,
                )
        with self.assertRaisesRegex(PublicationBlocked, "full SHA"):
            validate_actions_context(CONTEXT, INTENT, approved_control_sha="short")

    def test_live_target_requires_exact_repository_and_main_sha(self) -> None:
        self.assertTrue(
            verify_live_target_base(INTENT, fetch_json=public_api)["live_base_verified"]
        )

        def wrong_ref(path: str) -> dict:
            value = public_api(path)
            if path.endswith("/git/ref/heads/main"):
                value["object"]["sha"] = "f" * 40
            return value

        with self.assertRaisesRegex(PublicationBlocked, "live target base"):
            verify_live_target_base(INTENT, fetch_json=wrong_ref)

        def renamed_repo(path: str) -> dict:
            value = public_api(path)
            if path == "repos/dst-red-Wire/ecommerce-1":
                value["full_name"] = "attacker/ecommerce-1"
            return value

        with self.assertRaisesRegex(PublicationBlocked, "repository identity"):
            verify_live_target_base(INTENT, fetch_json=renamed_repo)

    def test_live_work_item_and_tracker_require_exact_open_issues(self) -> None:
        result = verify_live_work_item(INTENT, fetch_json=public_api)
        self.assertTrue(result["work_item_issue_verified"])
        self.assertTrue(result["tracker_issue_verified"])
        self.assertEqual(result["work_item_issue_body_sha256"], INTENT[
            "work_item_issue_body_sha256"
        ])

        def changed(path: str, issue_number: int, key: str, value: object) -> dict:
            observed = public_api(path)
            if path.endswith(f"/issues/{issue_number}"):
                observed[key] = value
            return observed

        for issue_number, key, value in (
            (188, "number", 189),
            (188, "number", True),
            (188, "state", "closed"),
            (188, "pull_request", {}),
            (188, "body", TEST_ISSUE_BODY + "changed"),
            (188, "body", None),
            (20, "number", 21),
            (20, "number", True),
            (20, "state", "closed"),
            (20, "pull_request", {}),
        ):
            with (
                self.subTest(issue=issue_number, key=key, value=value),
                self.assertRaises(PublicationBlocked),
            ):
                verify_live_work_item(
                    INTENT,
                    fetch_json=lambda path, issue_number=issue_number,
                    key=key, value=value: changed(
                        path, issue_number, key, value
                    ),
                )

    def test_marker_is_required_even_when_body_digest_matches(self) -> None:
        changed_body = TEST_ISSUE_BODY.replace("M7", "M8", 1)
        changed_intent = {
            **INTENT,
            "work_item_issue_body_sha256": hashlib.sha256(
                changed_body.encode("utf-8")
            ).hexdigest(),
        }

        def wrong_marker(path: str) -> dict:
            observed = public_api(path)
            if path.endswith("/issues/188"):
                observed["body"] = changed_body
            return observed

        with self.assertRaisesRegex(PublicationBlocked, "marker"):
            verify_live_work_item(changed_intent, fetch_json=wrong_marker)

    def test_work_item_identity_cannot_select_another_issue(self) -> None:
        with self.assertRaisesRegex(PublicationBlocked, "identity"):
            verify_live_work_item(
                {**INTENT, "work_item_issue": 189},
                fetch_json=lambda path: self.fail(
                    f"network called for unpinned issue: {path}"
                ),
            )

    def test_work_package_object_proof_is_mandatory_before_network(self) -> None:
        unproven = {**OBJECTS, "work_package_blob_sha256_verified": False}
        with (
            mock.patch("actions_publisher.load_intent", return_value=INTENT),
            mock.patch("actions_publisher.verify_bundle"),
            mock.patch("actions_publisher.inspect_objects", return_value=unproven),
            self.assertRaisesRegex(
                PublicationBlocked, "work_package_blob_sha256_verified"
            ),
        ):
            observe_publication(
                ROOT,
                context=CONTEXT,
                approved_control_sha=APPROVED_SHA,
                base_objects=ROOT,
                trusted_gnupg_home=ROOT,
                fetch_json=lambda path: self.fail(
                    f"network called before object proof: {path}"
                ),
            )

    def test_valid_observation_still_blocks_publication(self) -> None:
        with (
            mock.patch("actions_publisher.load_intent", return_value=INTENT),
            mock.patch("actions_publisher.verify_bundle"),
            mock.patch("actions_publisher.inspect_objects", return_value=OBJECTS),
        ):
            result = observe_publication(
                ROOT,
                context={**CONTEXT, "GITHUB_TOKEN": "unused-secret"},
                approved_control_sha=APPROVED_SHA,
                base_objects=ROOT,
                trusted_gnupg_home=ROOT,
                fetch_json=public_api,
            )
        self.assertEqual(result["status"], "BLOCKED_PUBLICATION_AUTHORITY")
        self.assertEqual(result["work_item_issue"], 188)
        self.assertTrue(result["work_item_issue_verified"])
        self.assertTrue(result["tracker_issue_verified"])
        self.assertEqual(result["tracker_issue"], 20)
        self.assertTrue(result["live_base_verified"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["branch_pushed"])
        self.assertFalse(result["pr_created"])
        self.assertFalse(result["formal_preflight"])
        self.assertFalse(result["full_qualification"])
        self.assertNotIn("unused-secret", str(result))

    def test_changed_inspector_identity_blocks_before_network(self) -> None:
        wrong = {**OBJECTS, "tree_sha": "f" * 40}
        with (
            mock.patch("actions_publisher.load_intent", return_value=INTENT),
            mock.patch("actions_publisher.verify_bundle"),
            mock.patch("actions_publisher.inspect_objects", return_value=wrong),
            self.assertRaisesRegex(PublicationBlocked, "tree_sha"),
        ):
            observe_publication(
                ROOT,
                context=CONTEXT,
                approved_control_sha=APPROVED_SHA,
                base_objects=ROOT,
                trusted_gnupg_home=ROOT,
                fetch_json=lambda path: self.fail(
                    f"network called before exact identity: {path}"
                ),
            )

    def test_public_api_reader_never_sends_authorization(self) -> None:
        class Response:
            status = 200

            def __init__(self):
                self.headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, maximum: int) -> bytes:
                self.max_read = maximum
                return b'{"full_name":"dst-red-Wire/ecommerce-1"}'

        response = Response()
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch(
            "actions_publisher.urllib.request.build_opener", return_value=opener
        ):
            result = read_public_github_json("repos/dst-red-Wire/ecommerce-1")
        self.assertEqual(result["full_name"], "dst-red-Wire/ecommerce-1")
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(response.max_read, 65_537)

    def test_duplicate_json_keys_are_refused(self) -> None:
        class Response:
            status = 200

            def __init__(self):
                self.headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self, maximum: int) -> bytes:
                return b'{"full_name":"good","full_name":"bad"}'

        opener = mock.Mock()
        opener.open.return_value = Response()
        with (
            mock.patch(
                "actions_publisher.urllib.request.build_opener", return_value=opener
            ),
            self.assertRaisesRegex(PublicationBlocked, "invalid JSON"),
        ):
            read_public_github_json("repos/dst-red-Wire/ecommerce-1")

    def test_api_path_cannot_select_other_hosts_or_methods(self) -> None:
        with self.assertRaisesRegex(PublicationBlocked, "path"):
            read_public_github_json("https://attacker.example/anything")
        with self.assertRaisesRegex(PublicationBlocked, "path"):
            read_public_github_json("../repos/dst-red-Wire/ecommerce-1")


if __name__ == "__main__":
    unittest.main()
