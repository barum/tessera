# Export-Control Notice (ECCN 5D002 Self-Classification)

> **Status: ACTION REQUIRED — the one-time BIS/NSA notification email described below HAS NOT
> BEEN SENT.** The maintainer must send it at or before the moment this repository becomes
> publicly available, and keep a copy of the sent email on file. Until then, this document is
> a prepared compliance artifact, not evidence of completed notification.

## Self-classification

This repository (`tessera`, <https://github.com/barum/tessera>) contains working cryptographic
source code in eight languages (Python, C, C++, Go, Rust, TypeScript, Java, CPython extension),
including:

- **ML-KEM-1024** key encapsulation (FIPS 203) — TesseraSeal suites `0x01`, `0x02`, `0x06`
- **AES-256-GCM** authenticated encryption — TesseraSeal suite `0x01`
- **ChaCha20-Poly1305** authenticated encryption — TesseraSeal suite `0x02`
- **X25519** key agreement — TesseraSeal hybrid suite `0x06`
- **SHAKE-256 / Keccak** hashing — TesseraHash, key derivation and commitment in TesseraSeal
- **Argon2id** password-based key derivation — TesseraSeal keyfile format

This is encryption source code that the maintainer self-classifies as **ECCN 5D002** under the
U.S. Export Administration Regulations (EAR), Commerce Control List Category 5, Part 2.

## Publicly-available exemption

Under **15 CFR 734.3(b)(3)**, publicly available encryption source code classified under
ECCN 5D002 is **not subject to the EAR** once the notification requirement of
**15 CFR 742.15(b)** has been fulfilled (the same notification satisfies License Exception TSU,
**15 CFR 740.13(e)**, where that pathway applies). The conditions are:

1. The source code is published and available to the public without restriction (this
   repository is public on GitHub under the Apache-2.0 license — satisfied at publication).
2. A **one-time email notification** is sent to the U.S. Bureau of Industry and Security (BIS)
   and the NSA ENC Encryption Request Coordinator, providing the URL where the source code is
   available (or a copy of the code), **at or before the time** the code is made publicly
   available.
3. An updated notification is sent if the URL changes (e.g. a repository rename or move) —
   updates to the code itself at the same URL do **not** require re-notification.

## One-time notification email — ready to send

Send the following from the maintainer's address and retain the sent copy (and any
acknowledgement) permanently in the maintainer's records:

```text
To: crypto@bis.doc.gov, enc@nsa.gov
From: Bahram Samani <bsamani@samani.com>
Subject: 742.15(b) notification - publicly available encryption source code (Tessera)

Pursuant to 15 CFR 742.15(b) (and, where applicable, License Exception TSU under
15 CFR 740.13(e)), this is a one-time notification that publicly available encryption
source code, self-classified under ECCN 5D002, is available at the following URL:

    https://github.com/barum/tessera

Description: "Tessera" is a specification-first set of open-source reference
implementations of post-quantum-era formats, including ML-KEM-1024 (FIPS 203) key
encapsulation, AES-256-GCM and ChaCha20-Poly1305 authenticated encryption, X25519 key
agreement, SHAKE-256 hashing, and Argon2id key derivation, implemented in Python, C,
C++, Go, Rust, TypeScript, and Java. The source code is published without restriction
under the Apache License 2.0.

Notifying party: Bahram Samani (project maintainer)
Email: bsamani@samani.com
Date of public availability: <YYYY-MM-DD - FILL IN BEFORE SENDING>
```

## Maintainer checklist

- [ ] **NOT DONE:** send the notification email above to `crypto@bis.doc.gov` and
      `enc@nsa.gov` at/before public availability, with the date placeholder filled in.
- [ ] File the sent email (and any reply) in permanent maintainer records.
- [ ] If the repository URL ever changes, send an updated notification with the new URL.
- [ ] Keep this document updated if new cryptographic primitives are added to the suite
      (the existing notification covers updates at the same URL, but this inventory should
      stay accurate).

## Caveats

- This document records a **self-classification by the maintainer, who is not an export-control
  attorney**. It is not legal advice. Distributors and downstream users in other jurisdictions
  are responsible for their own compliance (e.g. EU dual-use Regulation 2021/821, national
  import controls on cryptography).
- The exemption covers the *source code as published*. Shipping compiled proprietary products
  that incorporate this code may carry separate obligations for the shipper.
