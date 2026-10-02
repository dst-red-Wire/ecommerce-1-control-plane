"""Owner-approved, bounded publication of one pinned bootstrap PR via an environment PAT.

This module is inert until called by a trusted workflow on protected control
main, after GitHub has admitted the job to its reviewed environment. It never
checks out or runs the candidate tree. Each write uses a fresh public snapshot
and a one-step plan; no success is reported without exact live readback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from actions_publisher import (
    PublicationBlocked,
    read_public_github_json,
    validate_actions_context,
    verify_live_target_base,
    verify_live_work_item,
)
from inspect_objects import GIT, _environment, _git, _run, inspect_objects
from publication_plan import (
    FEATURE_REF,
    PublicationPlanBlocked,
    plan_publication,
)
from verify_bundle import (
    MAX_BUNDLE_BYTES,
    VerificationBlocked,
    _pairs,
    _read_file,
    load_intent,
    verify_bundle,
)

TARGET = "dst-red-Wire/ecommerce-1"
API_ROOT = "https://api.github.com/"
GIT_URL = "https://github.com/dst-red-Wire/ecommerce-1.git"
PAGE_SIZE = 100
MAX_PAGES = 3
MAX_RESPONSE_BYTES = 2_097_152
TIMEOUT_SECONDS = 8
MAX_WRITES = 2


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


def _pat(token: str) -> None:
    if (
        type(token) is not str
        or not token.startswith("github_pat_")
        or not 32 <= len(token) <= 256
        or not token.isascii()
        or any(character.isspace() for character in token)
    ):
        raise PublicationBlocked("environment PAT has an invalid format")


def _request_json(
    path: str,
    *,
    token: str | None = None,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    allow_404: bool = False,
) -> tuple[int, Any]:
    base = "repos/" + TARGET
    allowed_public = {
        base,
        base + "/git/ref/heads/main",
        base + "/git/ref/heads/feat/controller-receipt-cutover",
    }
    allowed_pages = {
        base + f"/pulls?state=open&per_page={PAGE_SIZE}&page={page}"
        for page in range(1, MAX_PAGES + 1)
    }
    allowed = (
        (method == "GET" and path in allowed_public | allowed_pages)
        or (method == "GET" and path == "user" and token is not None)
        or (method == "POST" and path == base + "/pulls" and token is not None)
        or (
            method == "PATCH"
            and re.fullmatch(re.escape(base) + r"/pulls/[1-9][0-9]*", path)
            is not None
            and token is not None
        )
    )
    if not allowed:
        raise PublicationBlocked("GitHub API path or method is outside the target")
    if method == "GET" and payload is not None:
        raise PublicationBlocked("GET cannot carry a payload")
    data = None
    if payload is not None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(data) > 16_384:
            raise PublicationBlocked("GitHub write payload exceeds limit")
    headers = {
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "ecommerce-1-bootstrap-publisher",
        "X-GitHub-Api-Version": "2022-11-28",
        "Cache-Control": "no-cache",
    }
    if token is not None:
        _pat(token)
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        API_ROOT + path, data=data, headers=headers, method=method
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            if not response.headers.get("Content-Type", "").lower().startswith(
                "application/json"
            ):
                raise PublicationBlocked("GitHub API response is not JSON")
            declared = response.headers.get("Content-Length")
            if declared is not None and (
                not declared.isdecimal() or int(declared) > MAX_RESPONSE_BYTES
            ):
                raise PublicationBlocked("GitHub API response length is invalid")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if allow_404 and exc.code == 404:
            exc.close()
            return 404, None
        exc.close()
        raise PublicationBlocked("GitHub API request was rejected") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise PublicationBlocked("GitHub API request failed") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise PublicationBlocked("GitHub API response exceeds limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise PublicationBlocked("GitHub API returned invalid JSON") from None
    return status, value


def _public_snapshots() -> tuple[dict[str, Any], ...]:
    base_path = "repos/" + TARGET
    repository_status, repository = _request_json(base_path)
    if repository_status != 200 or type(repository) is not dict:
        raise PublicationBlocked("target repository snapshot is unavailable")
    main_status, main = _request_json(base_path + "/git/ref/heads/main")
    if main_status != 200 or type(main) is not dict:
        raise PublicationBlocked("main ref snapshot is unavailable")
    feature_status, feature = _request_json(
        base_path + "/git/ref/heads/feat/controller-receipt-cutover",
        allow_404=True,
    )
    if feature_status not in {200, 404} or (
        feature_status == 200 and type(feature) is not dict
    ):
        raise PublicationBlocked("feature ref snapshot is unavailable")

    pulls: list[dict[str, Any]] = []
    complete = False
    for page in range(1, MAX_PAGES + 1):
        status, data = _request_json(
            base_path + f"/pulls?state=open&per_page={PAGE_SIZE}&page={page}"
        )
        if status != 200 or type(data) is not list or len(data) > PAGE_SIZE:
            raise PublicationBlocked("open PR page is unavailable")
        if any(type(item) is not dict for item in data):
            raise PublicationBlocked("open PR page contains a non-object")
        pulls.extend(data)
        if len(pulls) > 256:
            raise PublicationBlocked("open PR inventory exceeds limit")
        if len(data) < PAGE_SIZE:
            complete = True
            break
    if not complete:
        raise PublicationBlocked("open PR pagination is incomplete")
    return (
        repository,
        {
            "repository": TARGET,
            "http_status": main_status,
            "ref": "refs/heads/main",
            "object": main["object"],
        },
        {
            "repository": TARGET,
            "http_status": feature_status,
            "ref": FEATURE_REF,
            "object": feature["object"] if feature is not None else None,
        },
        {
            "repository": TARGET,
            "http_status": 200,
            "query": "state=open",
            "complete": True,
            "items": pulls,
        },
    )


def _preflight(
    root: Path,
    *,
    context: Mapping[str, str],
    approved_control_sha: str,
    base_objects: Path,
    trusted_gnupg_home: Path,
    fetch_json: Callable[[str], dict[str, Any]],
) -> dict[str, Any]:
    intent = load_intent(root)
    verify_bundle(root, intent)
    validate_actions_context(
        context, intent, approved_control_sha=approved_control_sha
    )
    objects = inspect_objects(
        root, base_objects=base_objects, trusted_gnupg_home=trusted_gnupg_home
    )
    if objects.get("status") != "OBSERVED_OBJECTS_ONLY":
        raise PublicationBlocked("object inspection is inadmissible")
    for key in ("base_sha", "head_sha", "tree_sha", "bundle_sha256"):
        if objects.get(key) != intent[key]:
            raise PublicationBlocked("inspected object pin differs")
    for key in (
        "head_objects_verified",
        "introduced_signatures_verified",
        "base_ancestry_verified",
        "work_package_blob_sha256_verified",
    ):
        if objects.get(key) is not True:
            raise PublicationBlocked("signed object evidence is incomplete")
    verify_live_target_base(intent, fetch_json=fetch_json)
    verify_live_work_item(intent, fetch_json=fetch_json)
    return intent


def _plan(intent: dict[str, Any]) -> dict[str, Any]:
    return plan_publication(intent, *_public_snapshots())


def _verify_token_owner(token: str) -> None:
    status, user = _request_json("user", token=token)
    if status != 200 or type(user) is not dict or user.get("login") != "dst-red-Wire":
        raise PublicationBlocked("environment PAT does not identify target owner")


def _push_exact_head(
    root: Path,
    intent: dict[str, Any],
    *,
    base_objects: Path,
    trusted_gnupg_home: Path,
    token: str,
    recheck: Callable[[], None],
) -> None:
    source = _read_file(root / "bootstrap" / "source.bundle", MAX_BUNDLE_BYTES)
    if (
        len(source) != intent["bundle_bytes"]
        or hashlib.sha256(source).hexdigest() != intent["bundle_sha256"]
    ):
        raise PublicationBlocked("source bundle changed before push")
    askpass = root / "bootstrap" / "pat_askpass.py"
    if not askpass.is_file():
        raise PublicationBlocked("trusted askpass helper is absent")
    with tempfile.TemporaryDirectory(prefix="bootstrap-pat-push-") as directory:
        work = Path(directory)
        repo = work / "source.git"
        bundle = work / "source.bundle"
        bundle.write_bytes(source)
        env = _environment(
            base_objects=base_objects,
            trusted_gnupg_home=trusted_gnupg_home,
            work=work,
        )
        _run(
            [
                GIT, "init", "--bare", "--object-format=sha1",
                "--template=/dev/null", str(repo),
            ],
            cwd=work,
            env=env,
            label="temporary push repository",
        )
        _git(
            repo, ["bundle", "verify", str(bundle)],
            work=work, env=env, label="push bundle prerequisite",
        )
        imported = _git(
            repo, ["bundle", "unbundle", str(bundle)],
            work=work, env=env, label="push bundle import",
        )
        expected = (
            f"{intent['head_sha']} refs/heads/{intent['publication_branch']}\n"
        ).encode("ascii")
        if imported != expected:
            raise PublicationBlocked("push bundle ref differs from pin")
        commit_type = _git(
            repo, ["cat-file", "-t", intent["head_sha"]],
            work=work, env=env, label="push head object",
        )
        if commit_type != b"commit\n":
            raise PublicationBlocked("push head object is not a commit")
        recheck()
        push_env = dict(env)
        push_env["GIT_ASKPASS"] = str(askpass)
        push_env["BOOTSTRAP_TARGET_PAT"] = token
        _git(
            repo,
            [
                "-c", "credential.helper=",
                "-c", "http.followRedirects=false",
                "push", "--porcelain", "--no-verify", GIT_URL,
                f"{intent['head_sha']}:{FEATURE_REF}",
            ],
            work=work,
            env=push_env,
            label="bounded non-force branch push",
        )


def _write_pr(action: dict[str, Any], token: str) -> None:
    kind = action["kind"]
    if kind == "CREATE_PR":
        payload = {
            "title": action["title"],
            "head": action["head"],
            "base": action["base"],
            "body": action["body"],
            "draft": action["draft"],
        }
        status, result = _request_json(
            "repos/" + TARGET + "/pulls",
            token=token,
            method="POST",
            payload=payload,
        )
        if status != 201 or type(result) is not dict:
            raise PublicationBlocked("PR creation readback is invalid")
    elif kind == "UPDATE_PR_TITLE":
        number = action["number"]
        if type(number) is not int or number <= 0:
            raise PublicationBlocked("PR number is invalid")
        status, result = _request_json(
            "repos/" + TARGET + f"/pulls/{number}",
            token=token,
            method="PATCH",
            payload={"title": action["title"]},
        )
        if status != 200 or type(result) is not dict:
            raise PublicationBlocked("PR title update readback is invalid")
    else:
        raise PublicationBlocked("publisher write kind is not permitted")


def publish_bounded(
    root: Path,
    *,
    context: Mapping[str, str],
    approved_control_sha: str,
    base_objects: Path,
    trusted_gnupg_home: Path,
    token: str,
    fetch_json: Callable[[str], dict[str, Any]] = read_public_github_json,
) -> dict[str, Any]:
    """Perform at most two exact, freshly planned writes in the reviewed job."""
    _pat(token)
    actions: list[str] = []
    for _ in range(MAX_WRITES + 1):
        intent = _preflight(
            root,
            context=context,
            approved_control_sha=approved_control_sha,
            base_objects=base_objects,
            trusted_gnupg_home=trusted_gnupg_home,
            fetch_json=fetch_json,
        )
        plan = _plan(intent)
        action = plan["action"]
        kind = action["kind"]
        if kind == "NOOP":
            if plan["pr_number"] is None:
                raise PublicationBlocked("no exact bootstrap PR exists")
            return {
                "status": "EXACT_BOOTSTRAP_PR_OBSERVED",
                "target_repository": TARGET,
                "base_sha": intent["base_sha"],
                "head_sha": intent["head_sha"],
                "pr_number": plan["pr_number"],
                "actions": actions,
                "head_executed": False,
                "formal_preflight": False,
                "full_qualification": False,
            }
        if len(actions) >= MAX_WRITES:
            raise PublicationBlocked("bounded publication write count exceeded")
        if kind not in {"PUSH_REF_NON_FORCE", "CREATE_PR", "UPDATE_PR_TITLE"}:
            raise PublicationBlocked("publisher action differs from allowlist")

        def recheck(
            pinned_intent: dict[str, Any] = intent,
            pinned_action: dict[str, Any] = action,
        ) -> None:
            verify_live_target_base(pinned_intent, fetch_json=fetch_json)
            verify_live_work_item(pinned_intent, fetch_json=fetch_json)
            fresh = _plan(pinned_intent)
            if fresh["action"] != pinned_action:
                raise PublicationBlocked("publication state changed before write")

        _verify_token_owner(token)
        if kind == "PUSH_REF_NON_FORCE":
            _push_exact_head(
                root, intent, base_objects=base_objects,
                trusted_gnupg_home=trusted_gnupg_home,
                token=token, recheck=recheck,
            )
            expected_next = "CREATE_PR"
        else:
            recheck()
            _write_pr(action, token)
            expected_next = "NOOP"
        actions.append(kind)
        readback = _plan(intent)
        if readback["action"]["kind"] != expected_next:
            raise PublicationBlocked("post-write branch or PR readback differs")
    raise PublicationBlocked("publication did not converge within write limit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-objects", required=True, type=Path)
    parser.add_argument("--trusted-gnupg-home", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = publish_bounded(
            Path(__file__).resolve().parents[1],
            context=dict(os.environ),
            approved_control_sha=os.environ["APPROVED_CONTROL_SHA"],
            base_objects=args.base_objects,
            trusted_gnupg_home=args.trusted_gnupg_home,
            token=os.environ["BOOTSTRAP_TARGET_PAT"],
        )
    except (KeyError, VerificationBlocked, PublicationPlanBlocked):
        print("BLOCKED_AUTHORITY: publisher prerequisite failed", file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 - never expose secret-bearing traceback
        print("BLOCKED_AUTHORITY: unexpected publisher failure", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
