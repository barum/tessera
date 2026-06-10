# tessera-id — TypeScript reference implementation

TypeScript port of the TesseraID 41-byte sortable identifier (variants `0x01` Standard / `0x02` HLC).
See [../README.md](../README.md) for the format and [../CLAUDE.md](../CLAUDE.md) for invariants.

## Build and test

```bash
npm install
npm run build     # tsc -> dist/
npm test
```

## Usage

```ts
import { StandardGenerator, decodeBase64URL } from "./tessera_id";
const gen = new StandardGenerator();
const id = gen.next();
console.log(id.toBase64URL()); // 55-char canonical text form
```

Decoders validate the variant byte and the encoding pad bits at decode time; unknown variants raise
`UnknownVariantError`. Version 1.3.1, Apache-2.0.
