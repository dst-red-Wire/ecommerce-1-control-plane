# Source bundle audit

This records a local, read-only examination of the bundle from the historical
control-plane candidate. The bundle and target source are kept outside this
public branch and its Git history.

## Provenance and pins

- Historical control commit: `2b71a52dbce2de5c814850d7d871472abd31477f`.
- Historical blob: `bootstrap/source.bundle` (`1aec58396c3878d22b009645e8d2f7f483815505`).
- Format: Git bundle v2; 87,538 bytes; SHA-256
  `d1ac6d0b8bcb641e9dfe39090b3039c289a733005f8f38a19b4ed592712bfadc`.
- Required base: `29859406d056debcaab2c8fc7a353a00de987971`, checked against
  `dst-red-Wire/ecommerce-1` main during this audit.
- Carried ref: `refs/heads/feat/controller-receipt-cutover` at
  `b1ac8599ba9f746a7c194359e04f17a890098723`; its tree is
  `1424fcd7af8b626a84e533bf4eaf7e8678be8d22`.

## Reconstruction and coverage

The prerequisite was fetched read-only into an isolated bare repository. The
bundle passed `git bundle verify`; its imported object store passed
`git fsck --full --strict` and `git verify-pack`. No candidate code or hooks
were executed.

The original pack transports 88 objects: 5 commits, 40 trees, and 43 blobs.
It contains 61 deltas. Git's thin-pack repair added 35 prerequisite base
objects, so the repaired pack lists 123 entries; those extra entries are not
objects transported by the bundle. All 88 transported objects were read and
their Git object IDs recalculated. They match the complete `base..head`
reachable set, with no missing or unreachable transported object. The 35
prerequisite base objects were also read, ID-checked, and scanned. The
review included 30 intermediate blob versions absent from the final tree.

Gitleaks 8.30.1 scanned all 123 reconstructed contents (88 transported
and 35 prerequisite bases) with archive depth 5, decode depth 10, and full output redaction. It raised three `generic-api-key`
alerts in `services/product/go.sum`: transported object line 115 and base
object lines 105 and 194. Each line is a public Go module
checksum and was classified as a false positive. No actionable credential
was found in this covered content. The scan does not prove that every possible
secret is absent.

This audit proves object reconstruction and content inspection for this exact
bundle. It does not qualify or authorize the target bootstrap. The clean
control-plane checkout has no source delivery; its publisher blocks on the
missing bundle before receiving a publication credential.

All five new commits passed signature verification for fingerprint
`D0E9857876048A4E303B4972BA1BD2FFE663316C`. The head tree and final
work-package SHA-256
`b9d7ca6bdd222337a5b350262037c101b79e4c0fa71b03d371346c813f1b491b`
match `bootstrap/intent.json`.

## Earlier local bundle

An earlier historical blob, 51875d12dc01c45171c81b591a8d0a03b50f3fc0,
is a 77,107-byte Git bundle (SHA-256
d6d444d4ebe5aebf06da5ab62dd4f7f89820aa3a5580732259352671149d1220).
Its head is 751be43600a42f47c212e71a90f3e7b839864007. Its pack
checksum and bundle prerequisite check passed. Its 50 introduced objects
are a subset of the 88 objects in the current bundle and are covered by
the reconstructed-content scan. This earlier bundle also remains local.
