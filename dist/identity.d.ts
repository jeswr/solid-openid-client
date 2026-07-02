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
export declare const DEFAULT_SCOPE = "openid webid offline_access";
/**
 * Force `openid` into a scope string (OIDC requires it) and de-duplicate. Order otherwise
 * preserved. An empty / whitespace input falls back to {@link DEFAULT_SCOPE}.
 */
export declare function normalizeScope(scope: string | undefined): string;
/** Narrow the two client-identity shapes. A `StaticClient` may carry a secret / metadata. */
export declare function resolveIdentity(opts: CreateSolidOidcClientOptions): ClientIdentity;
/** True iff the identity carries a confidential client secret. */
export declare function hasSecret(id: ClientIdentity): id is ClientIdentity & {
    clientSecret: string;
};
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
export declare function selectClientAuth(identity: ClientIdentity, tokenEndpointAuthMethod: string | undefined): oidc.ClientAuth;
//# sourceMappingURL=identity.d.ts.map