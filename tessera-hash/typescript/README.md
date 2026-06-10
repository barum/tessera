# tessera-hash — TypeScript reference implementation

TypeScript port of the TesseraHash 73-byte SHAKE-256 content hash (variant `0x03`).
See [../README.md](../README.md) for the format and [../CLAUDE.md](../CLAUDE.md) for invariants.

SHAKE-256 is sourced from `node:crypto` (OpenSSL-backed) — Node 18+, Node-only (no browser build).

## Build and test

```bash
npm install
npm run build     # tsc -> dist/
npm test
```

## Usage

```ts
import { hashOnly, decodeBase64URL } from "./tessera_hash";
const h = hashOnly(Buffer.from("hello"));
console.log(h.toBase64URL()); // 98-char canonical text form
```

Text decoders validate the variant byte and pad bits at decode time. Version 1.3.1, Apache-2.0.
