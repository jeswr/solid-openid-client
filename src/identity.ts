// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Client-identity, scope, and client-authentication policy — the pure decisions that shape HOW the
 * client presents itself to the OP, isolated from the flow orchestration so a reviewer can read
 * them as policy over plain data:
 *
 *   - scope normalisation (force `openid`, de-dup),
 *   - the two client-identity shapes (Client ID Document URL vs a static/confidential client) and
 *     the https-URL constraint on the shorthand, and
 *   - the client-authentication method selection, which FAILS CLOSED rather than silently
 *     downgrading a public client / an unknown method to `none` or a posted secret.
 *
 * The only non-type dependency is `openid-client`'s client-auth constructors (a peer dep).
 */

import * as oidc from "openid-client";
import type { ClientIdentity, CreateSolidOidcClientOptions } from "./types.js";

/** Default scopes. `webid` is Solid-OIDC's WebID scope; `offline_access` yields a refresh token. */
export const DEFAULT_SCOPE = "openid webid offline_access";

/**
 * Force `openid` into a scope string (OIDC requires it) and de-duplicate. Order otherwise
 * preserved. An empty / whitespace input falls back to {@link DEFAULT_SCOPE}.
 */
export function normalizeScope(scope: string | undefined): string {
  if (scope === undefined || scope.trim() === "") {
    return DEFAULT_SCOPE;
  }
  const parts = scope.split(/\s+/).filter((s) => s.length > 0);
  if (!parts.includes("openid")) {
    parts.unshift("openid");
  }
  // De-dup, preserving first-seen order.
  return [...new Set(parts)].join(" ");
}

/** Narrow the two client-identity shapes. A `StaticClient` may carry a secret / metadata. */
export function resolveIdentity(opts: CreateSolidOidcClientOptions): ClientIdentity {
  if (opts.client !== undefined && opts.clientId !== undefined) {
    throw new Error(
      "createSolidOidcClient: supply EITHER `clientId` (a Client ID Document URL) OR `client`, not both.",
    );
  }
  if (opts.client !== undefined) {
    return opts.client;
  }
  if (opts.clientId !== undefined) {
    // The shorthand `clientId` is, by contract, a Solid Client Identifier Document URL — it MUST be
    // an absolute https: URL (the OP dereferences it). Validate it so a non-URL / non-https value is
    // a clear error rather than a confusing downstream failure (a roborev finding). An opaque /
    // statically-registered client id goes via the full `client` option instead.
    let u: URL;
    try {
      u = new URL(opts.clientId);
    } catch {
      throw new Error(
        `createSolidOidcClient: \`clientId\` shorthand must be an absolute https: Client Identifier ` +
          `Document URL (got "${opts.clientId}"). For an opaque/static client id, use the \`client\` option.`,
      );
    }
    if (u.protocol !== "https:") {
      throw new Error(
        `createSolidOidcClient: \`clientId\` shorthand must be an https: URL (got "${opts.clientId}"). ` +
          "For an opaque/static client id, use the `client` option.",
      );
    }
    return { clientId: opts.clientId };
  }
  throw new Error(
    "createSolidOidcClient: a client identity is required — pass `clientId` (a Client ID Document URL, the primary path) or a full `client`.",
  );
}

/** True iff the identity carries a confidential client secret. */
export function hasSecret(id: ClientIdentity): id is ClientIdentity & { clientSecret: string } {
  return (
    "clientSecret" in id &&
    typeof (id as { clientSecret?: unknown }).clientSecret === "string" &&
    (id as { clientSecret: string }).clientSecret.length > 0
  );
}

/**
 * Select the openid-client client-authentication method.
 *
 * A PUBLIC client (no secret) always uses `none`. A CONFIDENTIAL client honours its
 * `token_endpoint_auth_method` (from `clientMetadata`) so a client registered for
 * `client_secret_basic` works — not only `client_secret_post` (a roborev finding); the default for
 * a confidential client is `client_secret_post`. A `none` method on a client that nonetheless
 * carries a secret is honoured as requested. The JWT-assertion / mTLS methods are not wired here
 * (they need a private key / cert beyond a shared secret); request them via a future option.
 */
export function selectClientAuth(
  identity: ClientIdentity,
  tokenEndpointAuthMethod: string | undefined,
): oidc.ClientAuth {
  // No secret → public client. ONLY `none` (or unset) is supported without credential material:
  // a secret-based method without a secret, OR private_key_jwt / tls_client_auth (which need a
  // private key / client cert this package does not wire), would otherwise SILENTLY downgrade to
  // `none`. We fail closed so the caller fixes the metadata (a roborev finding).
  if (!hasSecret(identity)) {
    if (tokenEndpointAuthMethod !== undefined && tokenEndpointAuthMethod !== "none") {
      throw new Error(
        `createSolidOidcClient: token_endpoint_auth_method "${tokenEndpointAuthMethod}" is not ` +
          "supported for a public client (no `clientSecret`). A public client must use `none`; " +
          "private_key_jwt / tls_client_auth (which need a key/cert) are not implemented.",
      );
    }
    return oidc.None();
  }
  const secret = identity.clientSecret;
  switch (tokenEndpointAuthMethod) {
    case undefined: // default for a confidential client
    case "client_secret_post":
      return oidc.ClientSecretPost(secret);
    case "client_secret_basic":
      return oidc.ClientSecretBasic(secret);
    case "client_secret_jwt":
      return oidc.ClientSecretJwt(secret);
    case "none":
      return oidc.None();
    default:
      // An unrecognised / misspelled method must NOT silently fall back to posting the secret —
      // fail closed so the caller fixes the metadata (a roborev finding). private_key_jwt /
      // tls_client_auth need a key/cert beyond a shared secret and are not wired here.
      throw new Error(
        `createSolidOidcClient: unsupported token_endpoint_auth_method "${tokenEndpointAuthMethod}". ` +
          "Supported: client_secret_post (default), client_secret_basic, client_secret_jwt, none.",
      );
  }
}
