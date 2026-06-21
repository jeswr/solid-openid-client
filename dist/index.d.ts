/**
 * @jeswr/solid-openid-client — a Solid-OIDC engine wrapping panva's `openid-client` v6.
 *
 * Performs the Solid-OIDC authorization-code + PKCE + DPoP flow (issuer discovery, code exchange,
 * token refresh, a DPoP-attaching authed `fetch`) on top of the dominant, audited OIDC client,
 * composing `@jeswr/solid-dpop` for the RFC 9449 proof primitives. For server-side Node apps —
 * CLIs, backend services, bots, agents — that want to authenticate to a Solid pod without a
 * bespoke OIDC implementation.
 *
 * `openid-client` is a PEER dependency (you install + de-dupe your own copy). `@jeswr/solid-dpop`
 * is a normal dependency (bundled into the committed `dist/` for GitHub-branch installs).
 */
export { createSolidOidcClient, DEFAULT_MAX_REPLAY_BODY_BYTES, DEFAULT_SCOPE, type SolidOidcClient, } from "./client.js";
export { type CryptoKeyPairLike, type DpopKeyPair, generateDpopKeyPair, resourceDpopProof, toCryptoKeyPair, } from "./dpop.js";
export type { AuthorizationRequest, AuthorizationRequestState, CallbackInput, ClientIdDocumentClient, ClientIdentity, CreateSolidOidcClientOptions, FetchLike, SolidOidcSession, SolidOidcTokens, StaticClient, } from "./types.js";
//# sourceMappingURL=index.d.ts.map