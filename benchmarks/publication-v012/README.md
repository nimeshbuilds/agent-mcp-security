# Pre-publication credential and private-data audit

**Verdict: no observed credential or private-data blocker** in the audited snapshot. This is a bounded inspection, not a guarantee that every secret is absent. No credential was tried against a live service, and no repository visibility, history, release or source file was changed by the audit.

The [sanitized receipt](publication-audit.json) records commit `6c0f4b818ffb03a8f40e6ceb29a1bcb504837bb1`, exact artifact hashes, observations and manual classifications. Later changes require an incremental check.

## Scope and results

| Surface | Actual coverage | Result |
| --- | --- | --- |
| Tracked snapshot | 497 files, 43,852,885 bytes | 11 Gitleaks observations; all classified as deliberate synthetic fixtures or one non-secret pattern match |
| Reachable Git history | 22 commits, 861 unique blobs; all remote branches and release tags resolve inside this history | 12 Gitleaks observations; same synthetic test classes, no unresolved credential candidate |
| Commit messages | Every reachable commit message | No Gitleaks findings |
| Releases | All seven assets across v0.11.0 and v0.12.0, including separately unpacked wheels | No Gitleaks findings; every asset named in the published checksum files matched |
| PDFs | All 11 distinct reachable historical/current PDFs, plus the duplicate release PDF | Extracted page text, annotation fields and metadata scanned; no secret, email or private home-path finding |
| Raster metadata | Five brand/report-cover PNGs | No email or private host path in metadata |
| Public benchmark provenance | Eight pinned public projects, 4,120 exported files | Every source byte/hash verified against the frozen manifests; all eight upstream license notices present |

Gitleaks **8.30.1**, binary SHA-256 `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f`, ran with its default rules, an explicit empty ignore file, ignored inline allow comments, full redaction, archive depth 3 and decoding depth 5. The history command used `--log-opts="--all --full-history"`. A finding exit code of 1 is retained in the receipt rather than rewritten as a clean scanner result. The zero-blocker conclusion follows manual classification of those observations.

## What the flagged material was

- Private-key detector fixtures contain markers with missing, short or repeated-character dummy material; they do not represent usable keys.
- Token detector, redaction and loopback TLS fixtures contain explicit synthetic canaries on reserved example/test hosts. The inspector regression matched variable formatting, without a credential literal.
- Apparent home paths in OpenHands reports are relative public UI source paths containing a `home` directory. Other home paths are named synthetic path-sanitization fixtures.
- Email-shaped matches in compressed PDF bytes disappeared when the documents were decoded; text, fields and metadata contained no matching identity. Remaining matches occur in synthetic test identities and URL-credential rejection cases.
- The tracked Claude login receipt records a sanitized outcome only. No credential files, raw auth logs, OAuth authorization URLs/codes, private source exports or ignored scratch files occur among the historical file paths.

The receipt contains paths, line numbers, classifications and hashes, but no secret values or raw terminal/model output. Temporary audit inputs, downloaded inspection copies and redacted raw reports were deleted after inspection. Ordinary author Git metadata is not treated as a secret.

## Publication and limits

[NOTICE.md](../../NOTICE.md) preserves third-party ownership and makes clear that this original project has no selected open-source license; public visibility alone does not grant reuse rights. The licensed Semgrep rule pack remains untracked, and benchmark reports include the retained upstream source notices. No additional redistribution blocker was observed in this inventory.

This audit excludes ignored local caches, unreachable Git objects, GitHub Actions secrets/artifacts and unrelated services. It did not OCR raster image pixels. It does not certify legal compliance, security of the scanner, or absence of every possible secret. Recheck changed files and assets before publishing a different snapshot.
