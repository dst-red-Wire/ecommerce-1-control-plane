# Owner operations for the bootstrap control plane

This PR contains control code and contracts only. The target Git bundle is
kept in a local archive branch and is absent from the public proposal.
This PR configures no source delivery, provisions no environment publication
credential or APPROVED_CONTROL_SHA, and creates no target branch or PR. The proposed workflow
is manual only and fails closed on the missing bundle before its publication
step. None of these review steps grants publisher or runner authority.

## Review of this control-only PR

1. Confirm the PR changes only the control repository and that its new
   history contains no target source or bundle. Check the signed commit and
   the exact reviewed tree.
2. Confirm the control main rule requires a PR and owner review, blocks
   force pushes, deletion, direct pushes and administrator bypass.
3. Confirm the target ecommerce-1 main rule applies to administrators and
   has no bypass for the future publication identity. A fine-grained PAT
   cannot be scoped to one branch.
4. Confirm the ecommerce-1-bootstrap-publisher environment has only
   dst-red-Wire as required reviewer, Prevent self-review, no administrator
   bypass, and Selected branches and tags containing only Branch: main.
5. Review and, if approved, merge this code-only PR through the protected
   path. A merge does not authorize dispatch or publication. Review
   CODEOWNERS enforcement once it reaches main.

## Separate future activation

Stop here until an independently reviewed, immutable source delivery is
defined. It must supply the exact 87,538-byte bundle whose SHA-256 is pinned
in bootstrap/intent.json without committing source to this public repository,
fetching a moving ref, or giving target HEAD any credential. The present
workflow has no such delivery step and cannot publish from a clean checkout.

After source delivery, independent publisher review and runtime gates have
real evidence, the owner may separately consider activation:

1. Record the exact reviewed main commit as environment variable
   APPROVED_CONTROL_SHA. A workflow input cannot set or override it.
2. From a browser or device outside WSL, create a short-expiry fine-grained
   token owned by dst-red-Wire, with repository access only to ecommerce-1
   and Contents: read/write plus Pull requests: read/write. Grant no Actions,
   Administration, Secrets or Workflows permissions.
3. Put it only in the ecommerce-1-bootstrap-publisher environment secret
   BOOTSTRAP_TARGET_PAT. Never copy its value into chat, WSL, logs or Git.
4. Sign in as myname37 to dispatch the reviewed workflow from main.
   dst-red-Wire approves the deployment from outside WSL after checking
   the exact control SHA and work item. An owner-initiated run cannot
   self-approve.
5. Read back the exact target branch and draft PR. Revoke the temporary
   token when that publication ends. The target PR still requires its own
   qualification, CODE/SECURITY review and merge authority.
6. Migrate other devices that use GitHub CLI before considering any global
   revocation of the owner's GitHub CLI OAuth authorization. WSL is logged
   out, and the retained owner SSH key no longer authenticates.

The cumulative resource budgets, same-boundary isolated preflight, real
PostgreSQL fixture, and remaining governance checks are separate blockers.
No active target publisher, runner authority, or target publication is
claimed by this PR.
