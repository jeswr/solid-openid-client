/**
 * The DPoP-attaching authed `fetch` — the resource-leg adapter of the Solid-OIDC flow, factored
 * out of the client so this security-critical runtime path reads as ONE named unit with EXPLICIT
 * dependencies (rather than a 100-line closure buried in the factory). It is the resource-side
 * counterpart to openid-client's token-leg: it builds each request's RFC 9449 §4.2 proof (with the
 * `ath` access-token binding) via `@jeswr/solid-dpop`, and retries once on a §8 `DPoP-Nonce`
 * challenge.
 *
 * Its invariants (essential security complexity — preserved verbatim, not flattened):
 *   - the DPoP token is NEVER sent over a plaintext URL (transport asserted BEFORE any header/proof);
 *   - `Request` + `init` are merged faithfully (an explicit `init` field overrides the `Request`'s);
 *   - the body is BUFFERED once up front so the §8 retry can REPLAY it (a stream would otherwise be
 *     consumed by the first attempt);
 *   - the access token is read LIVE per call (via `getAccessToken`) so a proof always binds to the
 *     current token, including after a refresh.
 */
import type { DpopKeyPair } from "@jeswr/solid-dpop";
import type { FetchLike } from "./types.js";
/** Everything the authed `fetch` needs, injected explicitly so it has no hidden state. */
export interface AuthedFetchDeps {
    /**
     * Read the CURRENT access token (or `undefined` before any login). Read live per request so a
     * proof binds to the latest token after a refresh; `undefined` means "no token yet" → throw.
     */
    readonly getAccessToken: () => string | undefined;
    /** The DPoP keypair the tokens are bound to (its thumbprint == the token `jkt`). */
    readonly dpopKeyPair: DpopKeyPair;
    /** Whether http-on-loopback is permitted (dev). https is otherwise required (no plaintext token). */
    readonly allowInsecure: boolean;
    /** Cap (bytes) on a buffered stream body for §8 replay. */
    readonly maxReplayBodyBytes: number;
    /** The underlying DOM-shaped fetch (test seam / SSRF-guarded fetch in prod). */
    readonly userFetch: FetchLike;
}
/**
 * Build the DPoP-attaching authed `fetch`. Binds every request to the current access token (`ath`)
 * and retries once on a server `DPoP-Nonce` challenge (RFC 9449 §8). Throws if called before any
 * token is available.
 *
 * It handles a `Request` input AND an `init` faithfully: the effective method/headers/body are
 * resolved from BOTH (an explicit `init` field overrides the `Request`'s), so a `POST`/`PUT`
 * `Request` passed with no `init` keeps its method + body (a bug fixed per a roborev finding).
 * The body is BUFFERED once up front (to a string/ArrayBuffer) so the §8 nonce retry can replay
 * it — a non-replayable stream body would otherwise be consumed by the first attempt.
 */
export declare function createAuthedFetch(deps: AuthedFetchDeps): FetchLike;
//# sourceMappingURL=authed-fetch.d.ts.map