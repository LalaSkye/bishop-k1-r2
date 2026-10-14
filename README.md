# 🏰 BISHOP K1 R2 — The Arthurian Engineering Project

**Source-available engineering candidate · © 2026 Ricky Jones (claimed rights holder).**

BISHOP K1 R2 is a Python canonical JSON byte-format **codec**, not the integrated Bishop protected-writer system. The source is offered for transparent examination and eligible non-commercial evaluation. **It is not production-ready.**

## What is included

- `src/k1_codec_R2.py` — exact 13,742-byte source candidate, unchanged from the reviewed/tested copy; SHA-256 `ebd500052c1f00903b19fa8342d7fbd8efd13c0109f299629f939738adcbcc6f`
- `LICENSE.md` — unmodified **PolyForm Strict License 1.0.0** text
- `NOTICE.md` — rights claim, contributor acknowledgement and disclosure boundary
- `PROVENANCE.json` and `SHA256SUMS.txt` — integrity information (not digital signatures)

The implementation provides `encode_k1`, `decode_k1` and `k1_sha256_hex`. It implements an iterative parser/renderer to avoid the deep-nesting recursion failure observed in R1.

## The four Arthurian guards

**Round Table:** contributions and claims recorded without inventing authorship.  
**Royal Seal:** published SHA-256 identity; a cryptographically signed release has **not** yet been established.  
**Crown Ledger:** bounded evidence with explicit limitations.  
**Gate:** rights and permissions before commercial use.

## Evidence ceiling

A previously supplied Lala-run harness transcript reported **92/92 checks passed**, including one check comparing **200,000 R2/R1 differential cases** (zero disagreements). That run was root-labelled (UID 0), reviewed and executed by the same evaluator, and **not independently reproduced**. The harness and raw transcript are **not distributed in this public-facing subset** while their rights are checked. Independent reviewers therefore cannot reproduce those exact claims from this subset alone.

This module does **not** validate service schemas, enforce the 65,536-byte service frame, verify signatures, check authority, provide OS isolation, launch a protected writer, or establish Bishop Stage A/Stage B safety.

The source header's `NOT TESTED` designation documents its *creation-time* state; the later reported harness result is a separate evidence claim, not a retroactive source edit.

## Rights and permitted use

See **the unmodified `LICENSE.md`**. PolyForm Strict 1.0.0 grants permitted non-commercial uses including personal research/experiments/testing as defined there, but does **not** grant general rights to distribute, modify, or make new works based on the software. Commercial uses need separate written permission from the rights holder. It is **not** an OSI open-source licence, and publication does not technically prevent copying or prevent GitHub forks.

Ownership/third-party rights must be checked before publication; a copyright notice or repository ownership is not by itself proof of legal title. This candidate grants no licence until a rights holder actually distributes it under the proposed terms.

## Verification

Check file digests against `SHA256SUMS.txt` in an independently controlled environment. A SHA-256 file digest establishes bytes, **not** the author's identity. No cryptographic author signature or signed release tag is supplied by this candidate package.

**Full Bishop contract candidates, source review history, R1 comparator and Lala's harness/transcript remain in the private engineering archive.**
