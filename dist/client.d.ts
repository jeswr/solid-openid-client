/**
 * The Solid-OIDC engine — wraps panva's `openid-client` v6 to perform the authorization-code +
 * PKCE + DPoP flow against a Solid OP, composing `@jeswr/solid-dpop` for the RFC 9449 proofs.
 *
 * The whole point: server-side Node apps (CLIs, services, bots, agents) get Solid-OIDC login on
 * top of a well-maintained, audited OIDC client instead of a bespoke implementation. We add only
 * the Solid-specific seams: the `webid` scope/claim, DPoP-by-default, the Client ID Document
 * public-client path, and a DPoP-attaching authed `fetch`.
 *
 * Security posture (this is an AUTH package — these are non-negotiable):
 *   - PKCE S256 ALWAYS (never omitted, regardless of `supportsPKCE()`).
 *   - `state` ALWAYS generated + validated exactly (CSRF).
 *   - `nonce` ALWAYS generated + validated exactly against the ID token (replay/binding).
 *   - DPoP asymmetric-only (ES256), enforced by `@jeswr/solid-dpop` key generation.
 *   - `webid` claim read fail-closed: a login with no resolvable WebID THROWS, never returns a
 *     session without one.
 *   - No token is ever logged.
 *   - `http:` issuers/endpoints rejected unless `allowInsecure` is explicitly set (dev loopback).
 */
import type { DpopKeyPair } from "@jeswr/solid-dpop";
import type { AuthorizationRequest, AuthorizationRequestState, CallbackInput, CreateSolidOidcClientOptions, FetchLike, SolidOidcSession, SolidOidcTokens } from "./types.js";
/** Default scopes. `webid` is Solid-OIDC's WebID scope; `offline_access` yields a refresh token. */
export declare const DEFAULT_SCOPE = "openid webid offline_access";
/**
 * The Solid-OIDC client handle returned by {@link createSolidOidcClient}. Stateful only insofar
 * as it holds the discovered configuration, the DPoP keypair, and (after a login/refresh) the
 * latest tokens — the consumer owns persistence (token storage is an injectable seam: persist
 * `currentTokens()` + `exportDpopKey()` yourself).
 */
export interface SolidOidcClient {
    /** The issuer this client authenticates against. */
    readonly issuer: string;
    /**
     * Build the authorization-request URL. Returns the URL plus the transient `state` (PKCE
     * verifier + `state` + `nonce` + redirectUri) that you MUST carry to {@link handleCallback}.
     *
     * @param extraParams optional additional authorization-request parameters (e.g. `prompt`).
     */
    authorizationUrl(extraParams?: Record<string, string>): Promise<AuthorizationRequest>;
    /**
     * Complete the flow: validate the redirect (state/PKCE/nonce), exchange the code for
     * DPoP-bound tokens, and read the `webid` claim (fail-closed). Returns the session.
     */
    handleCallback(callback: CallbackInput, state: AuthorizationRequestState): Promise<SolidOidcSession>;
    /**
     * Refresh using the stored (or supplied) refresh token, yielding a new DPoP-bound access token
     * (and possibly a rotated refresh token). Updates the client's current tokens.
     */
    refresh(refreshToken?: string): Promise<SolidOidcTokens>;
    /** The current DPoP-attaching authed `fetch`. Binds every request to the access token (`ath`). */
    readonly fetch: FetchLike;
    /** The current tokens (after a login/refresh), or `undefined` before any. */
    currentTokens(): SolidOidcTokens | undefined;
    /** The current authenticated WebID (after a login), or `undefined` before any. */
    currentWebId(): string | undefined;
    /** The DPoP keypair (for persistence — the refresh-token `jkt` binding requires the same key). */
    readonly dpopKeyPair: DpopKeyPair;
}
/**
 * Create a Solid-OIDC client. Discovers the issuer, prepares the DPoP keypair + openid-client
 * DPoP handle, and returns a handle exposing the auth-code flow + a DPoP-attaching authed fetch.
 *
 * Primary path: a Client ID Document public client — pass `clientId` as an `https:` URL serving
 * the client-id JSON-LD doc. (Dynamic client registration is a documented secondary seam: do the
 * registration yourself and pass the resulting `client` identity.)
 */
export declare function createSolidOidcClient(opts: CreateSolidOidcClientOptions): Promise<SolidOidcClient>;
//# sourceMappingURL=client.d.ts.map