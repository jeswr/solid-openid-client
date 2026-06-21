# Model provenance ledger — `@jeswr/solid-openid-client`

While Fable is unavailable, everything in this repo is authored by **Claude Opus 4.8** and tagged so
it can be targeted for re-review / upgrade when Fable returns.

- **Commit trailers:** `Model: claude-opus-4-8`,
  `Provenance: Opus 4.8 (Fable unavailable) — re-review/upgrade candidate`,
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **New source files:** an `AUTHORED-BY Claude Opus 4.8` top-of-file marker.

| Artifact | Authored by | Notes |
|---|---|---|
| `src/client.ts` | Claude Opus 4.8 | the Solid-OIDC engine — `createSolidOidcClient`, the auth-code/PKCE/DPoP flow, refresh, the DPoP-attaching authed `fetch`, the transport + fail-closed-WebID guards (security-critical) |
| `src/dpop.ts` | Claude Opus 4.8 | the DPoP bridge composing `@jeswr/solid-dpop` (keygen + resource-leg `ath` proof) with openid-client's DPoP handle |
| `src/types.ts` | Claude Opus 4.8 | the public type surface |
| `src/index.ts` | Claude Opus 4.8 | public barrel |
| `test/mockOp.ts` | Claude Opus 4.8 | the faithful Map-backed mock OP (real ES256 ID tokens, real JWKS, real PKCE S256 verification — the non-vacuity backbone of the security tests) |
| `test/client.test.ts` | Claude Opus 4.8 | 31 exhaustive auth tests (happy path, PKCE/state/nonce mismatch, fail-closed WebID, refresh round-trip, ath/jkt-bound authed fetch, §8 nonce retry) |
| `scripts/**` | Claude Opus 4.8 | self-contained dist build (esbuild, solid-dpop inlined) + check:dist + check:lockfile-transport |
| docs / config | Claude Opus 4.8 | README (incl. the design-decision record), suite.json, biome, tsconfig, vitest |

Phase-1 deliverable: the core Solid-OIDC authorization-code + PKCE + DPoP flow over panva's
`openid-client` v6, composing `@jeswr/solid-dpop` for RFC 9449 proofs. Advanced bits (dynamic client
registration, on-disk session store, a loopback-listener helper) are documented seams, not built —
the consumer supplies the client identity / persistence / redirect handling.
