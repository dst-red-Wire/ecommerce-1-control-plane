# Bootstrap work-item binding

The target bootstrap work item is open issue #188 in
https://github.com/dst-red-Wire/ecommerce-1. Its marker names M7, tracker
#20, package m7-isolated-pr-bootstrap, and the exact package path
config/work-packages/M7/m7-isolated-pr-bootstrap.yaml. The issue body lists
the 35 allowed paths, 17 acceptance tests, contracts, gates, and exit
criteria. It explicitly says an issue relation is not technical proof.

| Identity | Exact value |
| --- | --- |
| Target | dst-red-Wire/ecommerce-1 |
| Base | 29859406d056debcaab2c8fc7a353a00de987971 |
| Signed head | b1ac8599ba9f746a7c194359e04f17a890098723 |
| Tree | 1424fcd7af8b626a84e533bf4eaf7e8678be8d22 |
| Work item | #188, open |
| Work-item body SHA-256 | 7266035bab1c0df74bf4f288c9b093aecc38d129ca508dfd6a7f304cfebc9847 |
| Tracker | #20, open |
| Work package SHA-256 | b9d7ca6bdd222337a5b350262037c101b79e4c0fa71b03d371346c813f1b491b |

The new head adds the real PostgreSQL Product integration endpoint and the
work package to the earlier signed bootstrap stack. Trusted-base affected
classification selects Product because Makefile and repoctl change. The old
751be436 head still uses Testcontainers and cannot qualify without a
forbidden container-engine API. The owner explicitly authorized a new signed
head including the Product fix and updated work item.

An offline audit of the 87,538-byte Git bundle used the verified public
base and reconstructed every introduced object: 5 commits, 40 trees and
43 historical blobs, including 61 pack deltas. Full Git fsck and the five
introduced signatures passed. The HEAD tree and work-package blob digest
matched the pins. The 88 reconstructed objects were scanned directly, and
an offline Gitleaks scan of the five-commit range reported no findings.
These scans cannot certify that every possible secret is absent.

Both bundle versions remain reachable from the unpushed local archive
branch. This control-only PR excludes them and all
target source from its reachable history. The audit did not validate the issue relation under the
independent publisher authority, run preflight/FULL, or authorize target
publication. No immutable source transport is configured for the clean
control checkout. The protected publisher, cumulative resource budgets,
shared preflight/FULL boundary, bounded PostgreSQL fixture, and credential
separation still block a target branch push or PR.
