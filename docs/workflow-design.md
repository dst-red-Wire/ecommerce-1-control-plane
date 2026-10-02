# Bootstrap publisher workflow contract

Status: control-only PR proposal. Control main has no workflow at this stage.
The proposal listens only to manual workflow_dispatch, so a push or PR does
not run it. Its required source bundle is deliberately absent, and the
publisher fails closed before the credential-bearing step.

## Independent GitHub authority

The public control repository uses protected main. The owner must verify
that main requires a PR and a human review, disallows bypass, force pushes
and deletion, and rejects unreviewed workflow changes. The initial main
has no CODEOWNERS file, so its first publisher PR requires explicit owner
review under the generic review rule. After CODEOWNERS reaches main,
verify its enforcement before provisioning a publication secret.

The ecommerce-1-bootstrap-publisher environment has dst-red-Wire as its
required reviewer, prevents self-review and administrator bypass, and
admits only main. These settings were observed through the public GitHub
API. myname37 has write but not admin access and must start the dispatch;
the owner approves the deployment from a browser outside WSL. Only the
owner configures the environment and its secrets.

The owner records one approved control commit as the
APPROVED_CONTROL_SHA environment variable. The workflow rejects any
GITHUB_SHA or GITHUB_WORKFLOW_SHA that differs. No dispatch input may
override repository, base, branch, tree, work item or token scope.

## Temporary publication identity

The owner creates a short-lived fine-grained PAT with resource owner
dst-red-Wire, access only to dst-red-Wire/ecommerce-1, repository
permissions Contents: read/write and Pull requests: read/write, and
no additional repository permissions. The token is stored only as the
BOOTSTRAP_TARGET_PAT secret of ecommerce-1-bootstrap-publisher.
The control repository GITHUB_TOKEN has Contents: read only. The PAT
must never be passed to target HEAD, a target workflow, a pull_request
event job, a third-party action, a log or an artifact. The owner revokes
this PAT after the bootstrap branch and PR are created and read back.
A fine-grained PAT cannot restrict writes to a single branch. The
publisher code enforces the sole feature ref and the target main rule must
apply to administrators without bypass. Replacing the PAT with a short-lived
GitHub App token is later work.

GitHub environment protection delays access to the environment secret
until its required reviewer approves the job. Do not place the PAT in
repository or organization secrets. Do not place it in a workflow input.

## Trusted job and exact publication

Use workflow_dispatch on protected main, a fresh GitHub-hosted runner,
and no self-hosted runner. Do not use an unpinned action, reusable
workflow, package or downloaded script. Before any write, trusted
control code must check Actions event, actor, ref and approved control
SHA; obtain the exact source through a separately reviewed immutable,
digest-checked delivery mechanism; verify the fixed intent and byte-pinned
bundle; obtain only the
public target base as Git objects; verify exact ancestry, all introduced
GPG signatures, HEAD tree, and pinned work-package blob; re-read live
target main and open #188/#20; and inspect a complete open PR inventory.

The job must never checkout or execute target HEAD. It may import inert
Git objects into an isolated bare store for verification and the exact push.
It must disable Git hooks and config inheritance, bound Git/network
operations, and keep the token only in trusted code. Immediately before
each write, repeat live base, feature-ref and PR inventory reads and
re-run the pure one-step planner. Create only the exact feature ref via
non-force push. Then refresh snapshots and create a draft PR with the
pinned canonical work-item marker. Read back the ref and PR exact SHA,
source and base. Any mismatch is BLOCKED_AUTHORITY; a pushed branch is
not qualification.

This PR supplies no source transport, environment credential, or
APPROVED_CONTROL_SHA. The exact bundle digest, byte count, base, head and
tree are pinned in the intent, but those pins do not provide the bytes.
Do not commit the bundle here or fetch from a moving ref. A clean checkout
must block in source verification. The workflow must remain inactive until
the independent publisher,
strict cumulative resource supervisor, same-boundary isolated preflight,
real PostgreSQL fixture, hostile canaries and issue governance are
reviewable. A passing workflow will only publish. Exact-head FULL,
ChatGPT CODE, ChatGPT SECURITY, risk and owner authorization are later
gates. RUNNER_AUTHORITY remains NOT_ACTIVE.
