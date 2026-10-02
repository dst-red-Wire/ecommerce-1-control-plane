"""Hostile snapshot tests for the pure bootstrap publication planner."""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bootstrap"))

from publication_plan import (
    BASE_REF,
    FEATURE_REF,
    OPEN_PR_QUERY,
    PR_TITLE,
    PRE_WRITE_RECHECKS,
    PublicationPlanBlocked,
    plan_publication,
)
from verify_bundle import EXPECTED

INTENT = dict(EXPECTED)
REPOSITORY = {
    "full_name": INTENT["target_repository"],
    "default_branch": INTENT["target_default_branch"],
    "private": False,
    "archived": False,
    "disabled": False,
    "fork": False,
    "owner": {"login": "dst-red-Wire"},
}
BASE = {
    "repository": INTENT["target_repository"],
    "http_status": 200,
    "ref": BASE_REF,
    "object": {"type": "commit", "sha": INTENT["base_sha"]},
}
FEATURE_MISSING = {
    "repository": INTENT["target_repository"],
    "http_status": 404,
    "ref": FEATURE_REF,
    "object": None,
}
FEATURE_EXACT = {
    **FEATURE_MISSING,
    "http_status": 200,
    "object": {"type": "commit", "sha": INTENT["head_sha"]},
}
EMPTY_INVENTORY = {
    "repository": INTENT["target_repository"],
    "http_status": 200,
    "query": OPEN_PR_QUERY,
    "complete": True,
    "items": [],
}


def snapshot_pr(*, number: int = 189, title: str = PR_TITLE, body: str = "") -> dict:
    owner = INTENT["target_repository"].split("/", 1)[0]
    return {
        "number": number,
        "state": "open",
        "draft": True,
        "html_url": f"https://github.com/{INTENT['target_repository']}/pull/{number}",
        "title": title,
        "body": body,
        "head": {
            "ref": INTENT["publication_branch"],
            "sha": INTENT["head_sha"],
            "label": f"{owner}:{INTENT['publication_branch']}",
            "repo": {"full_name": INTENT["target_repository"]},
        },
        "base": {
            "ref": INTENT["target_default_branch"],
            "sha": INTENT["base_sha"],
            "label": f"{owner}:{INTENT['target_default_branch']}",
            "repo": {"full_name": INTENT["target_repository"]},
        },
    }


def decide(
    *,
    intent: dict | None = None,
    repository: dict | None = None,
    base: dict | None = None,
    feature: dict | None = None,
    inventory: dict | None = None,
) -> dict:
    return plan_publication(
        copy.deepcopy(INTENT if intent is None else intent),
        copy.deepcopy(REPOSITORY if repository is None else repository),
        copy.deepcopy(BASE if base is None else base),
        copy.deepcopy(FEATURE_MISSING if feature is None else feature),
        copy.deepcopy(EMPTY_INVENTORY if inventory is None else inventory),
    )


class PublicationPlanTests(unittest.TestCase):
    def test_absent_branch_plans_one_nonforce_ref_push(self) -> None:
        result = decide()
        self.assertEqual("PLANNED_NOT_AUTHORIZED", result["status"])
        self.assertEqual(
            {
                "kind": "PUSH_REF_NON_FORCE",
                "repository": INTENT["target_repository"],
                "ref": FEATURE_REF,
                "new_sha": INTENT["head_sha"],
                "force": False,
            },
            result["action"],
        )
        self.assertIsNone(result["pr_number"])
        self.assertEqual(PRE_WRITE_RECHECKS, result["recheck_immediately_before_write"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["head_executed"])
        self.assertNotIn("CREATE_PR", str(result["action"]))

    def test_exact_branch_without_pr_plans_only_creation(self) -> None:
        result = decide(feature=FEATURE_EXACT)
        action = result["action"]
        self.assertEqual("CREATE_PR", action["kind"])
        self.assertEqual("dst-red-Wire:feat/controller-receipt-cutover", action["head"])
        self.assertEqual("main", action["base"])
        self.assertTrue(action["draft"])
        self.assertIn(INTENT["head_sha"], action["body"])
        self.assertIn('"issue":188', action["body"])
        self.assertNotIn("PUSH_REF_NON_FORCE", str(action))

    def test_pr_body_has_exactly_one_canonical_work_item_marker(self) -> None:
        body = decide(feature=FEATURE_EXACT)["action"]["body"]
        marker = (
            '<!-- ecommerce-pr-work-item:v1 '
            '{"milestone":"M7","tracker_issue":20,"work_item_issue":188,'
            '"work_package_path":"config/work-packages/M7/m7-isolated-pr-bootstrap.yaml"} -->'
        )
        self.assertEqual(1, body.count("<!-- ecommerce-pr-work-item:v1 "))
        self.assertEqual(1, body.count(marker))
        self.assertEqual(1, body.count("<!-- ecommerce-bootstrap-pr:v1 "))

    def test_unrelated_open_work_item_pr_does_not_claim_bootstrap(self) -> None:
        unrelated_body = (
            '<!-- ecommerce-pr-work-item:v1 '
            '{"milestone":"M7","tracker_issue":20,"work_item_issue":187,'
            '"work_package_path":"config/work-packages/M7/m7-other-work.yaml"} -->'
        )
        unrelated = snapshot_pr(number=187, body=unrelated_body)
        unrelated["head"]["ref"] = "feat/other-work-item"
        unrelated["head"]["sha"] = "f" * 40
        unrelated["head"]["label"] = "dst-red-Wire:feat/other-work-item"
        inventory = {**EMPTY_INVENTORY, "items": [unrelated]}
        self.assertEqual("PUSH_REF_NON_FORCE", decide(inventory=inventory)["action"]["kind"])
        self.assertEqual(
            "CREATE_PR",
            decide(feature=FEATURE_EXACT, inventory=inventory)["action"]["kind"],
        )

    def test_exact_existing_pr_is_idempotent_noop(self) -> None:
        canonical_body = decide(feature=FEATURE_EXACT)["action"]["body"]
        pr = snapshot_pr(body=canonical_body)
        result = decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [pr]})
        self.assertEqual({"kind": "NOOP"}, result["action"])
        self.assertEqual(189, result["pr_number"])
        self.assertEqual((), result["recheck_immediately_before_write"])

    def test_only_exact_existing_pr_title_can_be_updated(self) -> None:
        canonical_body = decide(feature=FEATURE_EXACT)["action"]["body"]
        pr = snapshot_pr(title="old title", body=canonical_body)
        result = decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [pr]})
        self.assertEqual(
            {"kind": "UPDATE_PR_TITLE", "repository": INTENT["target_repository"],
             "number": 189, "title": PR_TITLE},
            result["action"],
        )
        self.assertEqual(PRE_WRITE_RECHECKS, result["recheck_immediately_before_write"])

    def test_wrong_feature_tip_and_changed_base_block(self) -> None:
        with self.assertRaisesRegex(PublicationPlanBlocked, "another tip"):
            decide(feature={**FEATURE_EXACT, "object": {"type": "commit", "sha": "f" * 40}})
        with self.assertRaisesRegex(PublicationPlanBlocked, "ref SHA"):
            decide(base={**BASE, "object": {"type": "commit", "sha": "f" * 40}})

    def test_wrong_repository_and_intent_block(self) -> None:
        for changed in (
            {**REPOSITORY, "full_name": "attacker/ecommerce-1"},
            {**REPOSITORY, "owner": {"login": "attacker"}},
            {**REPOSITORY, "private": True},
            {**REPOSITORY, "archived": True},
        ):
            with self.subTest(changed=changed), self.assertRaises(PublicationPlanBlocked):
                decide(repository=changed)
        with self.assertRaisesRegex(PublicationPlanBlocked, "intent"):
            decide(intent={**INTENT, "head_sha": "f" * 40})

    def test_ref_snapshot_must_identify_the_exact_source(self) -> None:
        for feature in (
            {**FEATURE_MISSING, "repository": "attacker/ecommerce-1"},
            {**FEATURE_MISSING, "ref": "refs/heads/main"},
            {**FEATURE_MISSING, "http_status": True},
            {**FEATURE_MISSING, "object": {"type": "commit", "sha": INTENT["head_sha"]}},
            {**FEATURE_EXACT, "object": {"type": "tag", "sha": INTENT["head_sha"]}},
        ):
            with self.subTest(feature=feature), self.assertRaises(PublicationPlanBlocked):
                decide(feature=feature)

    def test_inventory_must_be_complete_open_and_from_target(self) -> None:
        for inventory in (
            {**EMPTY_INVENTORY, "complete": False},
            {**EMPTY_INVENTORY, "repository": "attacker/ecommerce-1"},
            {**EMPTY_INVENTORY, "query": "state=closed"},
            {**EMPTY_INVENTORY, "http_status": 206},
            {**EMPTY_INVENTORY, "items": "not a list"},
        ):
            with self.subTest(inventory=inventory), self.assertRaises(PublicationPlanBlocked):
                decide(inventory=inventory)

    def test_concurrent_or_wrong_source_pr_blocks(self) -> None:
        canonical_body = decide(feature=FEATURE_EXACT)["action"]["body"]
        exact = snapshot_pr(body=canonical_body)
        wrong_source = copy.deepcopy(exact)
        wrong_source["head"]["repo"]["full_name"] = "attacker/ecommerce-1"
        wrong_base = copy.deepcopy(exact)
        wrong_base["base"]["sha"] = "f" * 40
        wrong_head = copy.deepcopy(exact)
        wrong_head["head"]["sha"] = "f" * 40
        for pr in (wrong_source, wrong_base, wrong_head):
            with self.subTest(pr=pr), self.assertRaisesRegex(
                PublicationPlanBlocked, "bootstrap PR source"
            ):
                decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [pr]})
        second = snapshot_pr(number=190, body=canonical_body)
        with self.assertRaisesRegex(PublicationPlanBlocked, "concurrent"):
            decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [exact, second]})

    def test_marker_hijack_and_existing_body_drift_block(self) -> None:
        canonical_body = decide(feature=FEATURE_EXACT)["action"]["body"]
        altered = snapshot_pr(body=canonical_body + "changed")
        with self.assertRaisesRegex(PublicationPlanBlocked, "body differs"):
            decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [altered]})
        hijack = snapshot_pr(number=190, body=canonical_body)
        hijack["head"]["ref"] = "other-branch"
        with self.assertRaisesRegex(PublicationPlanBlocked, "bootstrap PR source"):
            decide(feature=FEATURE_EXACT, inventory={**EMPTY_INVENTORY, "items": [hijack]})
        issue_claim = snapshot_pr(number=191, body="References #188")
        issue_claim["head"]["ref"] = "competing-branch"
        issue_claim["head"]["sha"] = "f" * 40
        with self.assertRaisesRegex(PublicationPlanBlocked, "bootstrap PR source"):
            decide(feature=FEATURE_EXACT,
                   inventory={**EMPTY_INVENTORY, "items": [issue_claim]})
        work_item_marker = canonical_body.split("\n")[1]
        marker_claim = snapshot_pr(number=192, body=work_item_marker)
        marker_claim["head"]["ref"] = "competing-branch"
        marker_claim["head"]["sha"] = "f" * 40
        with self.assertRaisesRegex(PublicationPlanBlocked, "bootstrap PR source"):
            decide(feature=FEATURE_EXACT,
                   inventory={**EMPTY_INVENTORY, "items": [marker_claim]})
        altered_marker = work_item_marker.replace(
            "config/work-packages/M7/m7-isolated-pr-bootstrap.yaml",
            "config/work-packages/M7/forged.yaml",
        ).replace('"work_item_issue":188', '"work_item_issue": 188')
        marker_claim["body"] = altered_marker
        with self.assertRaisesRegex(PublicationPlanBlocked, "bootstrap PR source"):
            decide(feature=FEATURE_EXACT,
                   inventory={**EMPTY_INVENTORY, "items": [marker_claim]})

    def test_pr_without_source_ref_and_duplicate_number_block(self) -> None:
        canonical_body = decide(feature=FEATURE_EXACT)["action"]["body"]
        exact = snapshot_pr(body=canonical_body)
        with self.assertRaisesRegex(PublicationPlanBlocked, "source ref is absent"):
            decide(inventory={**EMPTY_INVENTORY, "items": [exact]})
        duplicate = snapshot_pr(body=canonical_body)
        with self.assertRaisesRegex(PublicationPlanBlocked, "duplicated"):
            decide(feature=FEATURE_EXACT,
                   inventory={**EMPTY_INVENTORY, "items": [exact, duplicate]})

    def test_inputs_are_not_mutated(self) -> None:
        input_values = [copy.deepcopy(INTENT), copy.deepcopy(REPOSITORY),
                        copy.deepcopy(BASE), copy.deepcopy(FEATURE_EXACT),
                        copy.deepcopy(EMPTY_INVENTORY)]
        before = copy.deepcopy(input_values)
        plan_publication(*input_values)
        self.assertEqual(before, input_values)


if __name__ == "__main__":
    unittest.main()
