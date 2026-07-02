/**
 * The identity + token-type security core, isolated so a reviewer can audit the two fail-closed
 * invariants this package must never violate, independent of the flow orchestration:
 *
 *   1. WEBID PROVENANCE — a session's WebID is read ONLY from the VERIFIED ID token, never from the
 *      client-opaque access token; a login with no resolvable http(s) WebID THROWS.
 *   2. DPOP-DOWNGRADE GUARD — a token response whose `token_type` is not `dpop` is REJECTED, so an
 *      OP cannot silently downgrade a sender-constrained flow to a bearer token.
 *
 * These are pure functions over the openid-client token response (no I/O, no state). They are
 * exercised exhaustively by the fail-closed rejection suite.
 */
import type * as oidc from "openid-client";
import type { SolidOidcTokens } from "./types.js";
/** True iff `value` parses as an http(s) URL. WebIDs MUST be dereferenceable http(s) IRIs. */
export declare function isHttpUri(value: string): boolean;
/**
 * Read the `webid` claim — Solid-OIDC's WebID — from the token response, FAIL-CLOSED.
 *
 * SECURITY: the WebID is read ONLY from the **verified ID token** (`claims()` — openid-client has
 * already validated its signature against the OP JWKS plus `iss`/`aud`/`nonce`). We deliberately do
 * NOT fall back to the access token: a client does not (and must not) verify the access token's
 * signature — that is the resource server's job — so trusting a `webid` claim parsed from a
 * client-opaque access token would let an unsigned / attacker-shaped token establish a session
 * identity. The Solid-OIDC spec advertises the WebID in the ID token `webid` claim (or `sub` when
 * `sub` is itself the WebID); both are read here from the verified ID token. If neither yields an
 * `http(s)` WebID, we THROW — a session is never returned without a verified, resolvable WebID.
 */
export declare function extractWebIdOrUndefined(tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): string | undefined;
/** {@link extractWebIdOrUndefined}, but THROWS fail-closed when no verified WebID is present. */
export declare function extractWebId(tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): string;
/**
 * Map an openid-client token response into our public {@link SolidOidcTokens}, ENFORCING that the
 * token is DPoP-bound.
 *
 * SECURITY (DPoP-downgrade guard): Solid-OIDC tokens are sender-constrained via DPoP. openid-client
 * / oauth4webapi accepts BOTH `bearer` and `dpop` token types, so an OP that (mistakenly or
 * maliciously) returns a plain `bearer` token to our DPoP-bound request would otherwise be stored
 * and exposed as a successful Solid session — silently dropping the proof-of-possession guarantee.
 * We FAIL CLOSED: a token response whose `token_type` is not `dpop` (case-insensitive per RFC) is
 * rejected (a roborev finding). Applies to both the code exchange and refresh.
 */
export declare function toSolidTokens(res: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers): SolidOidcTokens;
//# sourceMappingURL=webid.d.ts.map