"""Pure, single-step publication plan for the one pinned bootstrap PR.

The caller must first verify the intent, signed bundle objects, control job,
work item, and GitHub snapshots independently. A plan is never publication
authority. It contains no network, credential, Git, subprocess, or write path.
Each write requires fresh snapshots and a new plan immediately beforehand.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from verify_bundle import EXPECTED

TARGET_REPOSITORY = "dst-red-Wire/ecommerce-1"
BASE_REF = "refs/heads/main"
FEATURE_REF = "refs/heads/feat/controller-receipt-cutover"
OPEN_PR_QUERY = "state=open"
PR_TITLE = "M7: bootstrap independent PR qualification"
PR_MARKER_PREFIX = "<!-- ecommerce-bootstrap-pr:v1 "
PR_WORK_ITEM_MARKER_PREFIX = "<!-- ecommerce-pr-work-item:v1 "
MAX_OPEN_PRS = 256
PRE_WRITE_RECHECKS = (
    "protected control SHA, environment approval and selected-repository PAT scope",
    "verified intent, bundle objects, open work item and tracker",
    "target repository identity and exact main ref SHA",
    "feature ref absence or exact approved HEAD, with no other tip",
    "complete current open PR inventory and unique exact PR source",
    "re-run this planner on fresh snapshots before each write",
)


class PublicationPlanBlocked(ValueError):
    """The snapshots cannot justify even a proposed bounded write."""


def _dict(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise PublicationPlanBlocked(f"{label} must be an object")
    return value


def _repository(snapshot: object, intent: dict[str, Any]) -> None:
    value = _dict(snapshot, "repository snapshot")
    if (
        value.get("full_name") != TARGET_REPOSITORY
        or value.get("default_branch") != intent["target_default_branch"]
        or value.get("private") is not False
        or value.get("archived") is not False
        or value.get("disabled") is not False
        or value.get("fork") is not False
    ):
        raise PublicationPlanBlocked("target repository identity or state differs")
    owner = _dict(value.get("owner"), "repository owner")
    if owner.get("login") != TARGET_REPOSITORY.split("/", 1)[0]:
        raise PublicationPlanBlocked("target repository owner differs")


def _ref(snapshot: object, *, ref: str, expected_sha: str | None) -> bool:
    value = _dict(snapshot, "ref snapshot")
    if set(value) != {"repository", "http_status", "ref", "object"}:
        raise PublicationPlanBlocked("ref snapshot fields differ")
    if value["repository"] != TARGET_REPOSITORY or value["ref"] != ref:
        raise PublicationPlanBlocked("ref snapshot source differs")
    if expected_sha is None and type(value["http_status"]) is int and value["http_status"] == 404:
        if value["object"] is not None:
            raise PublicationPlanBlocked("absent ref carries an object")
        return False
    if type(value["http_status"]) is not int or value["http_status"] != 200:
        raise PublicationPlanBlocked("ref snapshot status differs")
    obj = _dict(value["object"], "ref object")
    if obj.get("type") != "commit":
        raise PublicationPlanBlocked("ref is not a commit")
    if expected_sha is not None and obj.get("sha") != expected_sha:
        raise PublicationPlanBlocked("ref SHA differs from approved pin")
    return True


def _pr_body(intent: dict[str, Any]) -> str:
    marker = {
        "base_sha": intent["base_sha"],
        "head_sha": intent["head_sha"],
        "issue": intent["work_item_issue"],
        "tree_sha": intent["tree_sha"],
        "work_package_sha256": intent["work_package_sha256"],
    }
    work_item_marker = {
        "milestone": "M7",
        "tracker_issue": 20,
        "work_item_issue": intent["work_item_issue"],
        "work_package_path": intent["work_package_path"],
    }
    return (
        PR_MARKER_PREFIX + json.dumps(marker, sort_keys=True, separators=(",", ":"))
        + " -->\n"
        + PR_WORK_ITEM_MARKER_PREFIX
        + json.dumps(work_item_marker, sort_keys=True, separators=(",", ":"))
        + " -->\n\n"
        + "Work item: #188. Scope: the exact signed M7 bootstrap head.\n"
        + "Base and HEAD are pinned in the marker above.\n"
        + "Qualification, CODE, SECURITY and owner approval remain pending.\n"
        + "Rollback: close this PR and remove its feature ref after owner review.\n"
    )


def _work_item_marker_claims_bootstrap(body: str, intent: dict[str, Any]) -> bool:
    issue_field = re.compile(
        r'"work_item_issue"\s*:\s*'
        + re.escape(str(intent["work_item_issue"]))
        + r'(?=\s*[,}])'
    )
    for payload in re.findall(
        re.escape(PR_WORK_ITEM_MARKER_PREFIX) + r"(.*?)-->",
        body,
        flags=re.DOTALL,
    ):
        if issue_field.search(payload) or intent["work_package_path"] in payload:
            return True
    return False


def _pr_inventory(snapshot: object, intent: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = _dict(snapshot, "PR inventory")
    if set(inventory) != {"repository", "http_status", "query", "complete", "items"}:
        raise PublicationPlanBlocked("PR inventory fields differ")
    if (
        inventory["repository"] != TARGET_REPOSITORY
        or type(inventory["http_status"]) is not int
        or inventory["http_status"] != 200
        or inventory["query"] != OPEN_PR_QUERY
        or inventory["complete"] is not True
        or type(inventory["items"]) is not list
        or len(inventory["items"]) > MAX_OPEN_PRS
    ):
        raise PublicationPlanBlocked("complete open PR inventory is unavailable")
    candidates: list[dict[str, Any]] = []
    seen_numbers: set[int] = set()
    owner = TARGET_REPOSITORY.split("/", 1)[0]
    for item in inventory["items"]:
        pr = _dict(item, "PR")
        number = pr.get("number")
        if type(number) is not int or number <= 0 or number in seen_numbers:
            raise PublicationPlanBlocked("PR number is invalid or duplicated")
        seen_numbers.add(number)
        if pr.get("state") != "open" or type(pr.get("draft")) is not bool:
            raise PublicationPlanBlocked("PR state is not an open snapshot")
        if pr.get("html_url") != f"https://github.com/{TARGET_REPOSITORY}/pull/{number}":
            raise PublicationPlanBlocked("PR URL source differs")
        head = _dict(pr.get("head"), "PR head")
        base = _dict(pr.get("base"), "PR base")
        head_repo = _dict(head.get("repo"), "PR head repository")
        base_repo = _dict(base.get("repo"), "PR base repository")
        if (
            type(head.get("ref")) is not str
            or type(head.get("sha")) is not str
            or type(base.get("ref")) is not str
            or type(base.get("sha")) is not str
            or base_repo.get("full_name") != TARGET_REPOSITORY
        ):
            raise PublicationPlanBlocked("PR ref or target source is incomplete")
        body = pr.get("body")
        if body is not None and type(body) is not str:
            raise PublicationPlanBlocked("PR body type is invalid")
        claims_bootstrap = (
            head["ref"] == intent["publication_branch"]
            or head["sha"] == intent["head_sha"]
            or (type(body) is str and (
                PR_MARKER_PREFIX in body
                or _work_item_marker_claims_bootstrap(body, intent)
                or f"#{intent['work_item_issue']}" in body
            ))
        )
        if not claims_bootstrap:
            continue
        if (
            number == intent["work_item_issue"]
            or head_repo.get("full_name") != TARGET_REPOSITORY
            or head.get("label") != f"{owner}:{intent['publication_branch']}"
            or head["ref"] != intent["publication_branch"]
            or head["sha"] != intent["head_sha"]
            or base["ref"] != intent["target_default_branch"]
            or base["sha"] != intent["base_sha"]
            or base.get("label") != f"{owner}:{intent['target_default_branch']}"
        ):
            raise PublicationPlanBlocked("bootstrap PR source, head or base differs")
        candidates.append(pr)
    if len(candidates) > 1:
        raise PublicationPlanBlocked("concurrent bootstrap PRs exist")
    return candidates


def plan_publication(
    intent: Mapping[str, Any],
    repository_snapshot: Mapping[str, Any],
    base_ref_snapshot: Mapping[str, Any],
    feature_ref_snapshot: Mapping[str, Any],
    open_pr_inventory: Mapping[str, Any],
) -> dict[str, Any]:
    """Plan at most one bounded write from independently verified snapshots.

    A caller must repeat all mutable reads and this function just before the
    selected write, then read back exact ref/PR identity. A push is followed by
    a new plan; this plan never chains push and PR creation on stale snapshots.
    """
    if type(intent) is not dict or intent != EXPECTED:
        raise PublicationPlanBlocked("intent is not the exact verified pin")
    verified = dict(intent)
    if (
        verified["target_repository"] != TARGET_REPOSITORY
        or verified["target_default_branch"] != "main"
        or verified["publication_branch"] != "feat/controller-receipt-cutover"
        or verified["work_item_issue"] != 188
    ):
        raise PublicationPlanBlocked("publication scope differs from fixed bootstrap")
    _repository(repository_snapshot, verified)
    _ref(base_ref_snapshot, ref=BASE_REF, expected_sha=verified["base_sha"])
    feature_exists = _ref(feature_ref_snapshot, ref=FEATURE_REF, expected_sha=None)
    if feature_exists:
        obj = _dict(_dict(feature_ref_snapshot, "feature ref")["object"], "feature object")
        if obj.get("sha") != verified["head_sha"]:
            raise PublicationPlanBlocked("feature ref has another tip")
    candidates = _pr_inventory(open_pr_inventory, verified)
    if not feature_exists and candidates:
        raise PublicationPlanBlocked("PR exists while its source ref is absent")
    body = _pr_body(verified)
    if not feature_exists:
        action: dict[str, Any] = {
            "kind": "PUSH_REF_NON_FORCE", "repository": TARGET_REPOSITORY,
            "ref": FEATURE_REF, "new_sha": verified["head_sha"], "force": False,
        }
        readback = ("feature ref resolves to exact approved HEAD",)
    elif not candidates:
        action = {
            "kind": "CREATE_PR", "repository": TARGET_REPOSITORY,
            "head": f"{TARGET_REPOSITORY.split('/', 1)[0]}:{verified['publication_branch']}",
            "base": verified["target_default_branch"],
            "title": PR_TITLE, "body": body, "draft": True,
        }
        readback = ("unique open PR has exact source, base, HEAD and marker",)
    else:
        pr = candidates[0]
        if pr.get("body") != body:
            raise PublicationPlanBlocked("existing bootstrap PR body differs from pin")
        if pr.get("title") != PR_TITLE:
            action = {
                "kind": "UPDATE_PR_TITLE", "repository": TARGET_REPOSITORY,
                "number": pr["number"], "title": PR_TITLE,
            }
            readback = ("same PR number has exact title, source, base and HEAD",)
        else:
            action = {"kind": "NOOP"}
            readback = ()
    return {
        "status": "PLANNED_NOT_AUTHORIZED",
        "repository": TARGET_REPOSITORY,
        "base_sha": verified["base_sha"],
        "head_sha": verified["head_sha"],
        "feature_ref": FEATURE_REF,
        "pr_number": candidates[0]["number"] if candidates else None,
        "action": action,
        "recheck_immediately_before_write": PRE_WRITE_RECHECKS if action["kind"] != "NOOP" else (),
        "readback_after_write": readback,
        "publication_authorized": False,
        "head_executed": False,
    }


__all__ = [
    "BASE_REF", "FEATURE_REF", "OPEN_PR_QUERY", "PRE_WRITE_RECHECKS", "PR_TITLE",
    "PublicationPlanBlocked", "plan_publication",
]
