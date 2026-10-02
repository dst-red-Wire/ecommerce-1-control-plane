# ecommerce-1 control plane

This public repository contains a proposed, pinned publisher for
dst-red-Wire/ecommerce-1. The PR branch carries control code and contracts
only. It does not carry bootstrap/source.bundle or target source. The old
candidate and its bundle are preserved through an unpushed local archive
branch.

## Current state

The control repository has a protected main, and the publisher environment
requires review by dst-red-Wire. The workflow in this proposal has only a
manual workflow_dispatch trigger. A push or PR does not run it.

The publisher is **not operational** from this checkout: its required
bootstrap/source.bundle is deliberately absent. The workflow verifies
that byte-pinned input before the step that receives the publication
credential, so the missing input blocks publication. No source delivery
mechanism is configured, no environment credential or
APPROVED_CONTROL_SHA is provisioned by this proposal, and no target branch
or PR is created.

bootstrap/intent.json pins the target repository, base, publication branch,
signed HEAD, tree, signer fingerprint, work item #188, bundle SHA-256 and
byte count. These are immutable identifiers for a future reviewed source
delivery; they are not permission to fetch a moving branch or to run target
code. A future delivery must be separately reviewed, supply the exact bytes
outside this public Git history, and pass the same object and authority
checks. Neither the trusted job nor its publication credential is given to
the target HEAD.

## Local checks

Run from this checkout:

    python3 -m unittest discover -s tests -v
    ruff check bootstrap tests
    python3 -m compileall -q bootstrap tests
    git diff --check

Running bootstrap/verify_bundle.py is expected to report
BLOCKED_AUTHORITY: source bundle is not provisioned until an approved
source delivery exists. It is not a passing readiness check for this PR.

## Authority boundary

The control repository GITHUB_TOKEN is read only. Any future publication
credential belongs solely in the protected environment after owner review;
it never belongs in Git, workflow input, logs, artifacts, WSL, or the target
HEAD. The fixed publisher permits only the pinned feature ref and a draft PR.
Target main protection must apply to the publishing identity without bypass.

See docs/workflow-design.md and docs/control-plane-operations.md for the
remaining source delivery and owner operated gates. Cumulative resource
budgets, same boundary isolated preflight, and a real PostgreSQL fixture
remain runtime blockers. No formal FULL result or runner authority is claimed.
