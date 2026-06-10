# Decision memo: "Tessera" name clearance

- **Date:** 2026-06-10
- **Remediation item:** TP-006 (P0, DECISION-REQUIRED) — see
  [docs/remediation-plan-2026-06-10.md](../remediation-plan-2026-06-10.md)
- **Ticket:** TESS (assign number on hand-off)
- **Status:** RESEARCHED — awaiting maintainer decision. Nothing has been renamed and nothing has been
  published; this memo records the live-web findings and the options.
- **Context:** The PQToolkit → Tessera rename (TESS-00001, commit `c97338d`) landed with no recorded name
  clearance. This memo is that record. It blocks TP-085..TP-094 (registry publishing).

## 1. Findings (live checks, 2026-06-10)

### 1.1 ConsenSys Tessera — the collision that prompted this item

- **Status: officially dead and archived.** The GitHub repository
  [Consensys/tessera](https://github.com/Consensys/tessera) carries the banner "⚠️ Project Deprecation ⚠️
  This repo will be archived on June 1, 2026" and is now **read-only (archived)** — confirmed by direct fetch
  on 2026-06-10, nine days after the archive date. The repo states plainly: "Tessera is no longer supported."
- **What it was:** a stateless Java private-transaction manager / privacy enclave for ConsenSys Quorum and
  Hyperledger Besu (enterprise blockchain privacy). Latest release `tessera-24.4.2` (2024-06-12), 196 stars.
- **Sunset rationale:** the
  [LF Decentralized Trust blog](https://www.lfdecentralizedtrust.org/blog/sunsetting-tessera-and-simplifying-hyperledger-besu)
  describes a 7-month deprecation that began September 2024 — privacy moved to app-layer solutions; Tessera
  "ha[s] not kept pace with advancements in the Ethereum ecosystem."
- **Category overlap with this project:** both are "encryption/privacy software named Tessera", so search
  results will mingle for years (8+ years of accumulated docs, Stack Overflow answers, Docker images,
  `consensys.github.io/tessera` API docs). But there is **no active product conflict**: the project is
  unsupported, archived, and its maintainers have publicly walked away from the name's use in this category.

### 1.2 Other software currently named Tessera

| Project | Category | Status | Namespace it occupies |
|---------|----------|--------|------------------------|
| [mojodna/tessera](https://github.com/mojodna/tessera) | tilelive-based map tile server (Node) | semi-dormant; npm last modified 2024-07-21, v0.15.5 | **npm `tessera`** |
| [tessera-metrics/tessera](https://github.com/tessera-metrics/tessera) (ex-Urban Airship) | Graphite dashboard front-end (Python/Flask) | dormant (2014-era project), v0.10.0 | **PyPI `tessera`** |
| [sensat/tessera](https://github.com/sensat/tessera) | 3D Tiles geometric-error CLI (Rust) | v0.1.0 published 2025-10-03, 277 downloads | **crates.io `tessera`** |
| [tessera-ui/tessera](https://github.com/tessera-ui/tessera) | cross-platform declarative UI library (Rust) | **active** — `tessera-ui` v2.5.0, updated 2026-01-07, ~13,000 downloads | crates.io `tessera-ui` + GitHub org `tessera-ui`, repo named `tessera` |
| Tessera (ex-Fractional.art) | NFT fractionalization platform (Paradigm-backed) | **shut down May 2023**; a co-founder was charged by the DOJ in a securities-manipulation case ([CoinDesk](https://www.coindesk.com/web3/2023/05/12/paradigm-backed-nft-ownership-platform-tessera-is-shutting-down), [The Block](https://www.theblock.co/post/230623/fractional-nft-project-tessera)) | brand only (defunct) |
| Tessera (DARPA XDATA / [OSTI](https://osti.gov/biblio/1324917-tessera-open-source-software-accelerated-data-science)) | data-science / data-vis environment | dormant | brand only |

Notable: the **`tessera-ui` Rust UI library is the only actively-growing software namesake** — different
category (GUI, not crypto), but it shares the crates.io search page and its GitHub repo is literally named
`tessera`. The **defunct Tessera NFT platform** is the second crypto-category namesake and carries a negative
press association (DOJ charges against a co-founder) that a search for "Tessera crypto" still surfaces.

### 1.3 Registry availability (HTTP status fetched 2026-06-10)

Checked via the registries' JSON APIs (`registry.npmjs.org/<name>`, `pypi.org/pypi/<name>/json`,
`crates.io/api/v1/crates/<name>`). `200` = taken, `404` = free.

| Name | npm | PyPI | crates.io |
|------|-----|------|-----------|
| `tessera` | **200 — taken** (mojodna tile server) | **200 — taken** (Graphite dashboard) | **200 — taken** (Sensat 3D Tiles) |
| `tessera-id` | 404 — **free** | 404 — **free** | 404 — **free** |
| `tessera-seal` | 404 — **free** | 404 — **free** | 404 — **free** |
| `tessera-hash` | 404 — **free** | 404 — **free** | 404 — **free** |

Variant-name notes:

- **PyPI** normalizes per PEP 503: reserving `tessera-id` also covers `tessera_id` / `tessera.id`
  (`tessera_id` confirmed 404).
- **crates.io** rejects new crates that differ from an existing crate only by `-`/`_`, so reserving
  `tessera-id` blocks `tessera_id` (confirmed 404 today).
- **npm** scope `@tessera/*` shows no packages (`@tessera/core` → 404), but a package-level 404 cannot prove
  the *org/scope* "tessera" is unclaimed — npm scope ownership is only verifiable by attempting to create the
  org. The crates.io `tessera-ui` project also exists on npm-adjacent surfaces; do not assume the scope is
  free.
- **Maven Central** (Java, `com.tessera.common` namespace in `common/java/`): Central requires proof of
  domain ownership for a `com.tessera` group ID — we do not own `tessera.com`. Publishing Java artifacts will
  need an `io.github.<owner>` group ID or a domain we actually control. (Go needs no registry — module paths
  are the GitHub URL.)

### 1.4 Trademark quick check (web-level only — NOT clearance)

USPTO's TESS search system was retired and replaced
([USPTO notice](https://www.uspto.gov/subscription-center/2023/retiring-tess-what-know-about-new-trademark-search-system));
this check was done via web search over USPTO-mirroring sources, per the remediation item.

- **Tessera Technologies, Inc.** — the major semiconductor-packaging/IP-licensing company (founded 1990,
  IPO 2003). It **rebranded to Xperi Corporation in February 2017**
  ([IP CloseUp](https://ipcloseup.com/2017/03/06/ip-licensing-leader-tessera-renamed-xperi-corp-in-rebranding-push/),
  [Wikipedia](https://en.wikipedia.org/wiki/Xperi)); the licensing arm is now Adeia. Its historic TESSERA
  marks were in semiconductor classes; whether any registration survives under Xperi/Adeia, or has lapsed
  since the 2017 rebrand, **cannot be established from a web search**.
- **TESSERA, Tessera Global LLC** — application serial
  [99404219](https://uspto.report/TM/99404219) covering *downloadable mobile applications* (social
  networking, photo sharing) — i.e., a **software-class (Class 9) application that appears live**. The
  uspto.report page returned HTTP 403 to automated fetch, so filing date and current status are unverified.
- **TESSERA, Reg. #5179517 (Grigorius Holdings SIA)** — registered 2017-04-11, **cancelled 2023-10-27**
  under Section 8 ([Trademarkia](https://www.trademarkia.com/tessera-87005385)).
- **Tessera Therapeutics, Inc.** — biotech ("gene writing"), 8 marks
  ([uspto.report](https://uspto.report/company/Tessera-Therapeutics-Inc)) — different class, low relevance.

**Honest limitation:** a web search establishes *known knowns* only. It cannot establish formal clearance:
it misses common-law (unregistered) marks, state registrations, EUIPO/WIPO filings, pending unpublished
applications, and likelihood-of-confusion analysis across related classes. **If this suite is ever
commercialized or trademark-registered, retain trademark counsel for a real USPTO + EUIPO search in the
software/crypto classes (Class 9, 42).** For a non-commercial open-source spec suite, the practical exposure
is a cease-and-desist forcing a rename — annoying, survivable, and exactly the cost just paid once in
TESS-00001.

## 2. Collision-risk assessment per surface

| Surface | Risk | Rationale |
|---------|------|-----------|
| npm bare `tessera` | n/a (taken) | Map tile server owns it; unrelated category; we never needed the bare name |
| npm `tessera-id`/`-seal`/`-hash` | **Low** | Free today; no similarly-named crypto package found |
| PyPI bare `tessera` | n/a (taken) | Dormant dashboard; unrelated category |
| PyPI hyphenated names | **Low** | Free today; PEP 503 covers underscore variants |
| crates.io bare `tessera` | n/a (taken) | 3D-tiles tool; unrelated |
| crates.io hyphenated names | **Low–Medium** | Free today, but the *active* `tessera-ui` library dominates crates.io search for "tessera" in the Rust ecosystem |
| Search/SEO, "tessera crypto" | **Medium** | ConsenSys Tessera's 8-year documentation footprint + the defunct NFT platform (with DOJ-press baggage) will shadow discoverability for years, even though both are dead |
| Trademark (non-commercial OSS) | **Low–Medium** | At least one live-looking Class 9 TESSERA application (Tessera Global LLC) + possible surviving Tessera Technologies registrations; unknowable without counsel |
| Trademark (if commercialized) | **Unknown — requires counsel** | Web check cannot clear this; treat as a hard gate before any commercial use |
| GitHub | **Low** | Repo already lives at `barum/tessera`; `tessera-ui` org exists but no conflict mechanism applies |

## 3. Options

### Option A — Keep "Tessera"; publish only hyphenated artifact names (RECOMMENDED)

Keep the suite name. Never publish a bare `tessera` package anywhere (it's taken on all three registries
anyway). All published artifacts use the project names that are free today: `tessera-id`, `tessera-seal`,
`tessera-hash`.

- **For:** the headline collision (ConsenSys Tessera) archived itself on 2026-06-01 and its stewards publicly
  abandoned the category; every artifact name we actually need is free on all three registries; the rename
  was just paid for (TESS-00001) and the wire labels (`pqcrypt v1 ...`) are frozen regardless; bare-name
  squatters are all in unrelated categories.
- **Against:** SEO shadow from dead namesakes; the crates.io "tessera" search page belongs to `tessera-ui`;
  residual trademark unknowns if the project ever goes commercial.
- **Cost:** near zero. **Residual risk:** Medium on discoverability, Low on registries, gated-on-counsel for
  commercial trademark use.

### Option B — Qualify the family name (e.g., `tessera-pq-*` or an npm scope)

Keep "Tessera" informally but publish under a qualifier: npm `@<org>/tessera-id`, or a `tessera-pq-id` style
prefix everywhere.

- **For:** maximum registry distinctiveness; sidesteps the `tessera-ui` search-page issue on crates.io.
- **Against:** uglier install names; crates.io has no scoping so the qualifier infects the crate name itself;
  diverges artifact names from directory/spec names (`tessera-id/` would ship as `tessera-pq-id`), a
  permanent documentation tax; doesn't reduce trademark exposure (the dominant element is still TESSERA).
- **Cost:** low now, perpetual friction later.

### Option C — Rename now, while it costs little

Pick a cleaner-cleared name and repeat TESS-00001 before any publish event.

- **For:** only moment a rename is cheap is before first publish; eliminates the SEO shadow and the
  trademark question in one move.
- **Against:** the strongest collision just died; every needed registry name is free; a second rename in two
  days torches naming credibility and burns P0 remediation time (TP-007..TP-012, CI restoration) on a
  cosmetic; any new name needs the same clearance work with no guarantee of a cleaner result.
- **Cost:** high (repo, docs, skills, memory, CI badges — the TESS-00001 receipt, again). **Risk removed:**
  partial at best.

## 4. Recommendation

**Option A.** Keep Tessera; treat hyphenated artifact names as the only publishable names; reserve them
immediately; gate any future *commercial* use of the mark on a counsel-led clearance search.

### Exact registry names to reserve (all verified free 2026-06-10)

| Registry | Names | Note |
|----------|-------|------|
| npmjs.com | `tessera-id`, `tessera-seal`, `tessera-hash` | optionally create an org scope as fallback if available |
| PyPI | `tessera-id`, `tessera-seal`, `tessera-hash` | PEP 503 auto-covers `tessera_id` etc.; Python import names stay `tessera_id`/`tessera_seal`/`tessera_hash` |
| crates.io | `tessera-id`, `tessera-seal`, `tessera-hash` | registration blocks `_`-variants automatically |

**Reservation must be a minimal real release, not an empty squat:** PyPI's PEP 541 and crates.io policy both
allow reclaiming squatted/empty names. Publish a genuine `0.1.0-alpha` (or `0.0.1`) of each that installs and
exposes at least the constants/decode path, with metadata pointing at the repo — that is a legitimate
placeholder. This is exactly TP-085..TP-094's packaging work; do the reservation as its first slice, soon —
the names are only free until someone else wants them.

Additional actions under Option A:

1. **Java group ID:** plan Maven publishing under `io.github.<owner>` (we cannot verify `com.tessera` domain
   ownership for Central); the *source* namespace `com.tessera.common` can stay, but the published group ID
   decision should land before TP-085+.
2. **Disambiguation line:** add one sentence to the root README: "Not related to ConsenSys/Quorum Tessera
   (archived 2026), the Tessera UI library for Rust, or Tessera Technologies (now Xperi)." Cheap, kills most
   of the Medium SEO risk at the point of contact.
3. **Trademark gate:** record in this memo (done) that commercial use or trademark registration of TESSERA
   requires counsel-led USPTO + EUIPO clearance in Classes 9/42 first.

## 5. Decision

- [ ] **Option A** — keep Tessera, hyphenated artifacts only, reserve the 9 registry names (recommended)
- [ ] Option B — qualify (`tessera-pq-*` / scoped)
- [ ] Option C — rename now

Decided by: ____________  Date: ____________

## Sources

- [Consensys/tessera (GitHub, archived)](https://github.com/Consensys/tessera)
- [LFDT: Sunsetting Tessera and simplifying Hyperledger Besu](https://www.lfdecentralizedtrust.org/blog/sunsetting-tessera-and-simplifying-hyperledger-besu)
- [Consensys Tessera API docs](https://consensys.github.io/tessera/)
- [mojodna/tessera — npm tile server](https://github.com/mojodna/tessera)
- [tessera-metrics/tessera — Graphite dashboard](https://github.com/tessera-metrics/tessera)
- [Urban Airship Tessera tour](https://urbanairship.github.io/tessera/docs/guides/tour/)
- [sensat/tessera — crates.io 3D Tiles tool](https://github.com/sensat/tessera)
- [tessera-ui/tessera — Rust UI library](https://github.com/tessera-ui/tessera)
- [CoinDesk: Tessera (NFT) shutting down](https://www.coindesk.com/web3/2023/05/12/paradigm-backed-nft-ownership-platform-tessera-is-shutting-down)
- [The Block: Fractional NFT project Tessera to shut down](https://www.theblock.co/post/230623/fractional-nft-project-tessera)
- [USPTO: Retiring TESS](https://www.uspto.gov/subscription-center/2023/retiring-tess-what-know-about-new-trademark-search-system)
- [uspto.report: TESSERA app 99404219 (Tessera Global LLC)](https://uspto.report/TM/99404219)
- [uspto.report: Tessera Therapeutics marks](https://uspto.report/company/Tessera-Therapeutics-Inc)
- [Trademarkia: TESSERA #5179517 (cancelled)](https://www.trademarkia.com/tessera-87005385)
- [IP CloseUp: Tessera renamed Xperi (2017)](https://ipcloseup.com/2017/03/06/ip-licensing-leader-tessera-renamed-xperi-corp-in-rebranding-push/)
- [Wikipedia: Xperi](https://en.wikipedia.org/wiki/Xperi)
- [OSTI: Tessera accelerated data science](https://osti.gov/biblio/1324917-tessera-open-source-software-accelerated-data-science)
- Registry API checks (2026-06-10): `registry.npmjs.org/{tessera,tessera-id,tessera-seal,tessera-hash}`,
  `pypi.org/pypi/<name>/json`, `crates.io/api/v1/crates/<name>` — statuses recorded in §1.3.
