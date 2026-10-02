"""Read-only GitHub Actions publication adapter for the pinned bootstrap proposal.

This module can validate the control-job context, the signed Git objects,
the work-package blob, and the live public target base. It deliberately has
no credential minting, push, PR write, checkout, or candidate execution path.
A separately reviewed change is required before publication can be enabled.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from inspect_objects import inspect_objects
from verify_bundle import VerificationBlocked, _pairs, load_intent, verify_bundle

API_BASE = "https://api.github.com/"
MAX_API_RESPONSE_BYTES = 65_536
API_TIMEOUT_SECONDS = 8
WORKFLOW_PATH = ".github/workflows/bootstrap-publisher.yml"
SHA1 = re.compile(r"^[0-9a-f]{40}$")


class PublicationBlocked(VerificationBlocked):
    """A publication prerequisite is absent or differs from its approved pin."""


def _exact(context: Mapping[str, str], key: str, expected: str) -> None:
    if context.get(key) != expected:
        raise PublicationBlocked(f"{key} differs from approved Actions context")


def validate_actions_context(
    context: Mapping[str, str],
    intent: Mapping[str, Any],
    *,
    approved_control_sha: str,
) -> dict[str, str]:
    """Validate identities visible to a future protected dispatch job.

    The approved control SHA must be supplied by a separately governed
    environment pin. Supplying it on a command line alone grants no authority.
    """
    if not SHA1.fullmatch(approved_control_sha):
        raise PublicationBlocked("approved control SHA is not a full SHA-1")
    _exact(context, "GITHUB_ACTIONS", "true")
    _exact(context, "GITHUB_EVENT_NAME", "workflow_dispatch")
    _exact(context, "GITHUB_REPOSITORY", str(intent["control_repository"]))
    _exact(context, "GITHUB_REF", f"refs/heads/{intent['control_default_branch']}")
    _exact(context, "GITHUB_REF_PROTECTED", "true")
    _exact(context, "GITHUB_SHA", approved_control_sha)
    _exact(context, "GITHUB_WORKFLOW_SHA", approved_control_sha)
    _exact(context, "GITHUB_ACTOR", str(intent["dispatch_actor"]))
    _exact(context, "GITHUB_TRIGGERING_ACTOR", str(intent["dispatch_actor"]))
    _exact(context, "RUNNER_ENVIRONMENT", "github-hosted")
    _exact(
        context,
        "GITHUB_WORKFLOW_REF",
        (
            f"{intent['control_repository']}/{WORKFLOW_PATH}"
            f"@refs/heads/{intent['control_default_branch']}"
        ),
    )
    return {
        "control_repository": str(intent["control_repository"]),
        "control_sha": approved_control_sha,
        "dispatch_actor": str(intent["dispatch_actor"]),
        "workflow_ref": context["GITHUB_WORKFLOW_REF"],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


def read_public_github_json(path: str) -> dict[str, Any]:
    """GET one fixed GitHub API path, without a token, proxy, or redirect."""
    if not re.fullmatch(
        r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?", path
    ):
        raise PublicationBlocked("GitHub API path is invalid")
    request = urllib.request.Request(
        API_BASE + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ecommerce-1-bootstrap-observer",
            "X-GitHub-Api-Version": "2022-11-28",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    try:
        with opener.open(request, timeout=API_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise PublicationBlocked("GitHub API response is not HTTP 200")
            if (
                not response.headers.get("Content-Type", "")
                .lower()
                .startswith("application/json")
            ):
                raise PublicationBlocked("GitHub API response is not JSON")
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None and (
                not declared_length.isdecimal()
                or int(declared_length) > MAX_API_RESPONSE_BYTES
            ):
                raise PublicationBlocked("GitHub API response length is invalid")
            data = response.read(MAX_API_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise PublicationBlocked("GitHub API read failed") from exc
    if len(data) > MAX_API_RESPONSE_BYTES:
        raise PublicationBlocked("GitHub API response exceeds byte limit")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PublicationBlocked("GitHub API returned invalid JSON") from exc
    if type(value) is not dict:
        raise PublicationBlocked("GitHub API returned a non-object")
    return value


def verify_live_target_base(
    intent: Mapping[str, Any],
    *,
    fetch_json: Callable[[str], dict[str, Any]] = read_public_github_json,
) -> dict[str, Any]:
    """Observe the exact public repository and its current default-branch tip."""
    repository_name = intent["target_repository"]
    branch = intent["target_default_branch"]
    if repository_name != "dst-red-Wire/ecommerce-1" or branch != "main":
        raise PublicationBlocked("target identity differs from adapter pin")
    repository = fetch_json(f"repos/{repository_name}")
    if (
        repository.get("full_name") != repository_name
        or repository.get("default_branch") != branch
        or repository.get("private") is not False
    ):
        raise PublicationBlocked("live target repository identity differs from pin")
    ref = fetch_json(f"repos/{repository_name}/git/ref/heads/{branch}")
    obj = ref.get("object")
    if (
        ref.get("ref") != f"refs/heads/{branch}"
        or type(obj) is not dict
        or obj.get("type") != "commit"
        or obj.get("sha") != intent["base_sha"]
    ):
        raise PublicationBlocked("live target base differs from pin")
    return {
        "target_repository": repository_name,
        "target_default_branch": branch,
        "live_base_sha": intent["base_sha"],
        "live_base_verified": True,
    }


def verify_live_work_item(
    intent: Mapping[str, Any],
    *,
    fetch_json: Callable[[str], dict[str, Any]] = read_public_github_json,
) -> dict[str, Any]:
    """Read the exact open work item and tracker without treating them as proof."""
    repository_name = intent.get("target_repository")
    issue_number = intent.get("work_item_issue")
    issue_body_sha256 = intent.get("work_item_issue_body_sha256")
    package_path = intent.get("work_package_path")
    if (
        repository_name != "dst-red-Wire/ecommerce-1"
        or type(issue_number) is not int
        or issue_number != 188
        or package_path
        != "config/work-packages/M7/m7-isolated-pr-bootstrap.yaml"
        or type(issue_body_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", issue_body_sha256) is None
    ):
        raise PublicationBlocked("work item identity differs from adapter pin")

    issue = fetch_json(f"repos/{repository_name}/issues/{issue_number}")
    if (
        type(issue.get("number")) is not int
        or issue["number"] != issue_number
        or issue.get("state") != "open"
        or "pull_request" in issue
    ):
        raise PublicationBlocked("live work item is not the pinned open issue")
    body = issue.get("body")
    if type(body) is not str:
        raise PublicationBlocked("live work item body is absent")
    marker_payload = {
        "category": "work-item",
        "milestone": "M7",
        "tracker_issue": 20,
        "work_package_id": "m7-isolated-pr-bootstrap",
        "work_package_path": package_path,
    }
    marker = (
        "<!-- ecommerce-work-item:v1 "
        + json.dumps(marker_payload, sort_keys=True, separators=(",", ":"))
        + " -->"
    )
    if (
        not body.startswith(marker + "\n")
        or body.count("<!-- ecommerce-work-item:v1 ") != 1
    ):
        raise PublicationBlocked("live work item marker differs from pin")
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != issue_body_sha256:
        raise PublicationBlocked("live work item body differs from digest pin")

    tracker = fetch_json(f"repos/{repository_name}/issues/20")
    if (
        type(tracker.get("number")) is not int
        or tracker["number"] != 20
        or tracker.get("state") != "open"
        or "pull_request" in tracker
    ):
        raise PublicationBlocked("live tracker is not open issue #20")
    return {
        "work_item_issue": issue_number,
        "work_item_issue_body_sha256": issue_body_sha256,
        "work_item_issue_verified": True,
        "tracker_issue": 20,
        "tracker_issue_verified": True,
    }


def observe_publication(
    root: Path,
    *,
    context: Mapping[str, str],
    approved_control_sha: str,
    base_objects: Path,
    trusted_gnupg_home: Path,
    fetch_json: Callable[[str], dict[str, Any]] = read_public_github_json,
) -> dict[str, Any]:
    """Observe prerequisites, then return a mandatory publication block.

    Every source and credential needed to lift the block requires a separate
    owner-reviewed publisher implementation. This function cannot publish.
    """
    intent = load_intent(root)
    verify_bundle(root, intent)
    action = validate_actions_context(
        context, intent, approved_control_sha=approved_control_sha
    )
    objects = inspect_objects(
        root,
        base_objects=base_objects,
        trusted_gnupg_home=trusted_gnupg_home,
    )
    for key in ("base_sha", "head_sha", "tree_sha", "bundle_sha256"):
        if objects.get(key) != intent[key]:
            raise PublicationBlocked(f"inspected {key} differs from pin")
    if objects.get("status") != "OBSERVED_OBJECTS_ONLY":
        raise PublicationBlocked("object inspection status is not admissible")
    for key in (
        "head_objects_verified",
        "introduced_signatures_verified",
        "base_ancestry_verified",
        "work_package_blob_sha256_verified",
    ):
        if objects.get(key) is not True:
            raise PublicationBlocked(f"{key} is not proven")
    live = verify_live_target_base(intent, fetch_json=fetch_json)
    work_item = verify_live_work_item(intent, fetch_json=fetch_json)
    return {
        "status": "BLOCKED_PUBLICATION_AUTHORITY",
        "reason": (
            "An owner-approved workflow, protected environment approval, "
            "and reviewed environment-only publication credential are absent."
        ),
        "control_repository": action["control_repository"],
        "control_sha": action["control_sha"],
        "target_repository": live["target_repository"],
        "base_sha": live["live_base_sha"],
        "head_sha": intent["head_sha"],
        "tree_sha": intent["tree_sha"],
        "work_item_issue": work_item["work_item_issue"],
        "work_item_issue_body_sha256": work_item["work_item_issue_body_sha256"],
        "work_item_issue_verified": True,
        "tracker_issue": work_item["tracker_issue"],
        "tracker_issue_verified": True,
        "work_package_path": intent["work_package_path"],
        "work_package_sha256": intent["work_package_sha256"],
        "bundle_sha256": intent["bundle_sha256"],
        "head_objects_verified": True,
        "work_package_blob_sha256_verified": True,
        "live_base_verified": True,
        "publication_authorized": False,
        "branch_pushed": False,
        "pr_created": False,
        "formal_preflight": False,
        "full_qualification": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-control-sha", required=True)
    parser.add_argument("--base-objects", required=True, type=Path)
    parser.add_argument("--trusted-gnupg-home", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = observe_publication(
            Path(__file__).resolve().parents[1],
            context=dict(os.environ),
            approved_control_sha=args.approved_control_sha,
            base_objects=args.base_objects,
            trusted_gnupg_home=args.trusted_gnupg_home,
        )
    except VerificationBlocked as exc:
        print(f"BLOCKED_AUTHORITY: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
