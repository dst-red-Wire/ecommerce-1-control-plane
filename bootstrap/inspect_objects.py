"""Offline inspection of the exact bootstrap bundle's Git objects.

This module reads objects and verifies introduced commit signatures. It does
not establish the live GitHub base, qualify a PR, or authorize publication.
No candidate tree is checked out or executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from verify_bundle import (
    MAX_BUNDLE_BYTES,
    VerificationBlocked,
    _read_file,
    _validate_header,
    load_intent,
    verify_bundle,
)

GIT = "/usr/bin/git"
GPG = "/usr/bin/gpg"
PRLIMIT = "/usr/bin/prlimit"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
MAX_OUTPUT_BYTES = 131_072
MAX_INTRODUCED_COMMITS = 128
COMMAND_TIMEOUT_SECONDS = 20.0


class ObjectInspectionBlocked(VerificationBlocked):
    """The bundle objects cannot be safely verified against the supplied base."""


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], label: str) -> bytes:
    try:
        process = subprocess.Popen(
            [
                PRLIMIT,
                "--cpu=15",
                "--as=805306368",
                "--fsize=67108864",
                "--nofile=128",
                "--",
                *argv,
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as exc:
        raise ObjectInspectionBlocked(f"{label}: tool unavailable") from exc

    output = bytearray()
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ObjectInspectionBlocked(f"{label}: timed out")
                if not selector.select(remaining):
                    raise ObjectInspectionBlocked(f"{label}: timed out")
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT_BYTES:
                    raise ObjectInspectionBlocked(f"{label}: output limit exceeded")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ObjectInspectionBlocked(f"{label}: timed out")
        if process.wait(timeout=remaining):
            raise ObjectInspectionBlocked(f"{label}: Git verification failed")
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObjectInspectionBlocked(f"{label}: bounded command failed") from exc
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


def _trusted_directory(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise ObjectInspectionBlocked(f"{label}: absolute path required")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ObjectInspectionBlocked(f"{label}: unavailable") from exc
    if not resolved.is_dir():
        raise ObjectInspectionBlocked(f"{label}: directory required")
    if any(character in str(resolved) for character in ("\n", "\r", ":")):
        raise ObjectInspectionBlocked(f"{label}: unsafe path")
    return resolved


def _environment(
    *, base_objects: Path, trusted_gnupg_home: Path, work: Path
) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(work),
        "XDG_CONFIG_HOME": str(work),
        "LC_ALL": "C",
        "GNUPGHOME": str(trusted_gnupg_home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_COUNT": "0",
        "GIT_TEMPLATE_DIR": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(base_objects),
    }


def _git(
    repo: Path, args: list[str], *, work: Path, env: dict[str, str], label: str
) -> bytes:
    return _run(
        [
            GIT,
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            f"gpg.program={GPG}",
            f"--git-dir={repo}",
            *args,
        ],
        cwd=work,
        env=env,
        label=label,
    )


def _one_sha(output: bytes, expected: str, *, label: str) -> None:
    if output.decode("ascii", errors="replace").strip() != expected:
        raise ObjectInspectionBlocked(f"{label}: object differs from pin")


def _verify_signature(
    repo: Path,
    commit: str,
    signer_fingerprint: str,
    *,
    work: Path,
    env: dict[str, str],
) -> None:
    try:
        output = _git(
            repo,
            ["verify-commit", "--raw", commit],
            work=work,
            env=env,
            label="commit signature",
        )
    except ObjectInspectionBlocked as exc:
        raise ObjectInspectionBlocked("commit signature invalid") from exc
    signatures = [
        line.split()[2].decode("ascii", errors="replace")
        for line in output.splitlines()
        if line.startswith(b"[GNUPG:] VALIDSIG ")
    ]
    if signatures != [signer_fingerprint]:
        raise ObjectInspectionBlocked("commit signer fingerprint differs from pin")



def _verify_work_package_blob(
    repo: Path,
    intent: dict[str, Any],
    *,
    work: Path,
    env: dict[str, str],
) -> bool:
    keys = ("work_item_issue", "work_package_path", "work_package_sha256")
    present = [key in intent for key in keys]
    if not any(present):
        return False  # Synthetic object-inspection fixtures may omit the package.
    if not all(present):
        raise ObjectInspectionBlocked("work package pin is incomplete")
    issue = intent["work_item_issue"]
    path = intent["work_package_path"]
    digest = intent["work_package_sha256"]
    if type(issue) is not int or issue <= 0:
        raise ObjectInspectionBlocked("work-item issue pin is invalid")
    if (
        type(path) is not str
        or re.fullmatch(r"[A-Za-z0-9_.\-/]+", path) is None
        or path.startswith("/")
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or ":" in path
    ):
        raise ObjectInspectionBlocked("work package path pin is invalid")
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ObjectInspectionBlocked("work package digest pin is invalid")
    data = _git(
        repo,
        ["cat-file", "blob", f"{intent['head_sha']}:{path}"],
        work=work,
        env=env,
        label="work package blob",
    )
    if len(data) > 16_384 or hashlib.sha256(data).hexdigest() != digest:
        raise ObjectInspectionBlocked("work package blob digest differs from pin")
    return True


def _inspect_bundle_objects(
    bundle_path: Path,
    intent: dict[str, Any],
    base_objects: Path,
    trusted_gnupg_home: Path,
) -> dict[str, Any]:
    """Inspect a bundle against explicitly supplied local trust inputs.

    This internal seam accepts synthetic pins for tests. The public entrypoint
    loads only the immutable production intent and byte pin.
    """
    for key in ("base_sha", "head_sha", "tree_sha"):
        if type(intent.get(key)) is not str or not SHA1.fullmatch(intent[key]):
            raise ObjectInspectionBlocked(f"{key}: invalid SHA-1 pin")
    signer = intent.get("signer_fingerprint")
    if type(signer) is not str or not re.fullmatch(r"[0-9A-F]{40}", signer):
        raise ObjectInspectionBlocked("signer fingerprint: invalid pin")
    branch = intent.get("publication_branch")
    if type(branch) is not str or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9/._-]*", branch
    ):
        raise ObjectInspectionBlocked("publication branch: invalid pin")
    if ".." in branch or branch.endswith(("/", ".", ".lock")) or "//" in branch:
        raise ObjectInspectionBlocked("publication branch: invalid pin")

    data = _read_file(bundle_path, MAX_BUNDLE_BYTES)
    if len(data) != intent.get("bundle_bytes"):
        raise ObjectInspectionBlocked("bundle byte count differs from pin")
    if hashlib.sha256(data).hexdigest() != intent.get("bundle_sha256"):
        raise ObjectInspectionBlocked("bundle digest differs from pin")
    _validate_header(data, intent)

    base_objects = _trusted_directory(base_objects, label="base objects")
    trusted_gnupg_home = _trusted_directory(
        trusted_gnupg_home, label="trusted GPG home"
    )
    if (base_objects / "info" / "alternates").exists() or (
        base_objects / "info" / "alternates"
    ).is_symlink():
        raise ObjectInspectionBlocked("base objects: chained alternates forbidden")
    if not (base_objects / "info").is_dir():
        raise ObjectInspectionBlocked("base objects: Git object directory required")
    if bundle_path.resolve().is_relative_to(
        base_objects
    ) or bundle_path.resolve().is_relative_to(trusted_gnupg_home):
        raise ObjectInspectionBlocked("trusted inputs overlap bundle")

    with tempfile.TemporaryDirectory(
        prefix="bootstrap-object-inspection-"
    ) as directory:
        work = Path(directory)
        repo = work / "objects.git"
        pinned_bundle = work / "source.bundle"
        with pinned_bundle.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        env = _environment(
            base_objects=base_objects, trusted_gnupg_home=trusted_gnupg_home, work=work
        )
        _run(
            [
                GIT,
                "init",
                "--bare",
                "--object-format=sha1",
                "--template=/dev/null",
                str(repo),
            ],
            cwd=work,
            env=env,
            label="temporary repository",
        )
        _one_sha(
            _git(
                repo,
                ["cat-file", "-t", intent["base_sha"]],
                work=work,
                env=env,
                label="base object",
            ),
            "commit",
            label="base object type",
        )
        _git(
            repo,
            ["bundle", "verify", str(pinned_bundle)],
            work=work,
            env=env,
            label="bundle prerequisite",
        )
        refs = _git(
            repo,
            ["bundle", "list-heads", str(pinned_bundle)],
            work=work,
            env=env,
            label="bundle ref",
        )
        expected_ref = f"{intent['head_sha']} refs/heads/{branch}\n".encode("ascii")
        if refs != expected_ref:
            raise ObjectInspectionBlocked("bundle ref differs from pin")
        unpacked = _git(
            repo,
            ["bundle", "unbundle", str(pinned_bundle)],
            work=work,
            env=env,
            label="bundle import",
        )
        if unpacked != expected_ref:
            raise ObjectInspectionBlocked("imported bundle ref differs from pin")
        _one_sha(
            _git(
                repo,
                ["cat-file", "-t", intent["head_sha"]],
                work=work,
                env=env,
                label="head object",
            ),
            "commit",
            label="head object type",
        )
        _one_sha(
            _git(
                repo,
                ["rev-parse", "--verify", f"{intent['head_sha']}^{{tree}}"],
                work=work,
                env=env,
                label="head tree",
            ),
            intent["tree_sha"],
            label="head tree",
        )
        _git(
            repo,
            ["merge-base", "--is-ancestor", intent["base_sha"], intent["head_sha"]],
            work=work,
            env=env,
            label="base ancestry",
        )
        raw_commits = _git(
            repo,
            [
                "rev-list",
                "--topo-order",
                "--reverse",
                f"{intent['base_sha']}..{intent['head_sha']}",
            ],
            work=work,
            env=env,
            label="introduced commit list",
        )
        commits = raw_commits.decode("ascii", errors="replace").splitlines()
        if (
            not commits
            or len(commits) > MAX_INTRODUCED_COMMITS
            or intent["head_sha"] not in commits
            or any(not SHA1.fullmatch(commit) for commit in commits)
            or len(set(commits)) != len(commits)
        ):
            raise ObjectInspectionBlocked(
                "introduced commit set is invalid or unbounded"
            )
        _git(
            repo,
            [
                "fsck",
                "--strict",
                "--no-reflogs",
                "--no-progress",
                "--full",
                "--no-dangling",
                intent["head_sha"],
            ],
            work=work,
            env=env,
            label="object integrity",
        )
        for commit in commits:
            _verify_signature(repo, commit, signer, work=work, env=env)
        work_package_verified = _verify_work_package_blob(
            repo, intent, work=work, env=env
        )

    return {
        "status": "OBSERVED_OBJECTS_ONLY",
        "base_sha": intent["base_sha"],
        "head_sha": intent["head_sha"],
        "tree_sha": intent["tree_sha"],
        "bundle_sha256": intent["bundle_sha256"],
        "introduced_commits_verified": len(commits),
        "head_objects_verified": True,
        "introduced_signatures_verified": True,
        "base_ancestry_verified": True,
        "work_item_issue": intent.get("work_item_issue"),
        "work_package_blob_sha256_verified": work_package_verified,
        "live_base_verified": False,
        "publication_authorized": False,
        "formal_preflight": False,
    }


def inspect_objects(
    root: Path, *, base_objects: Path, trusted_gnupg_home: Path
) -> dict[str, Any]:
    intent = load_intent(root)
    verify_bundle(root, intent)
    bundle_path = root / str(intent["bundle_path"])
    if base_objects.resolve().is_relative_to(
        root.resolve()
    ) or trusted_gnupg_home.resolve().is_relative_to(root.resolve()):
        raise ObjectInspectionBlocked(
            "trust inputs must be outside the control repository"
        )
    return _inspect_bundle_objects(
        bundle_path, intent, base_objects, trusted_gnupg_home
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-objects", required=True, type=Path)
    parser.add_argument("--trusted-gnupg-home", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = inspect_objects(
            Path(__file__).resolve().parents[1],
            base_objects=args.base_objects,
            trusted_gnupg_home=args.trusted_gnupg_home,
        )
    except VerificationBlocked as exc:
        print(f"BLOCKED_AUTHORITY: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
