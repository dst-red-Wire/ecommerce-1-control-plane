# Manual publisher proposal

bootstrap-publisher.yml is a control-only proposal. It has only a
workflow_dispatch trigger; pushes and pull requests do not run it. The
workflow can run only from the protected default branch after a reviewed
merge and environment approval.

The source bundle is intentionally absent from public Git. As committed,
the workflow fails its pinned source verification before the step that
receives the target publication credential. No source transport,
APPROVED_CONTROL_SHA, or publication credential is provisioned here.
A separate review must design an immutable, digest-checked delivery path
before this publisher can operate. Do not add target source to this repository.
