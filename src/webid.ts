// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
export function isHttpUri(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

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
export function extractWebIdOrUndefined(
  tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): string | undefined {
  // Verified ID-token claims ONLY — signature + iss/aud/nonce already checked by openid-client.
  const idClaims = tokenResponse.claims();

  // Primary: the `webid` claim.
  const fromWebidClaim = idClaims?.webid;
  if (typeof fromWebidClaim === "string" && isHttpUri(fromWebidClaim)) {
    return fromWebidClaim;
  }

  // Some Solid OPs set the WebID as the `sub` (when `sub` is itself the WebID). Still from the
  // VERIFIED ID token, so this is safe.
  const fromSub = idClaims?.sub;
  if (typeof fromSub === "string" && isHttpUri(fromSub)) {
    return fromSub;
  }

  return undefined;
}

/** {@link extractWebIdOrUndefined}, but THROWS fail-closed when no verified WebID is present. */
export function extractWebId(
  tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): string {
  const webId = extractWebIdOrUndefined(tokenResponse);
  if (webId !== undefined) {
    return webId;
  }
  throw new Error(
    "Solid-OIDC login produced no resolvable `webid` claim in the VERIFIED ID token; refusing to " +
      "return a session without a verified WebID (fail-closed). The WebID is never trusted from an " +
      "unverified access token.",
  );
}

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
export function toSolidTokens(
  res: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): SolidOidcTokens {
  if (res.token_type === undefined || res.token_type.toLowerCase() !== "dpop") {
    throw new Error(
      `Solid-OIDC requires DPoP-bound (sender-constrained) tokens, but the OP returned token_type ` +
        `"${res.token_type ?? "none"}". Refusing a non-DPoP token (fail-closed).`,
    );
  }
  const base: { accessToken: string; tokenType: string } = {
    accessToken: res.access_token,
    tokenType: res.token_type,
  };
  return {
    ...base,
    ...(res.refresh_token !== undefined ? { refreshToken: res.refresh_token } : {}),
    ...(res.id_token !== undefined ? { idToken: res.id_token } : {}),
    ...(res.expires_in !== undefined ? { expiresIn: res.expires_in } : {}),
    ...(res.scope !== undefined ? { scope: res.scope } : {}),
  };
}
