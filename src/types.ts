// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Public types for `@jeswr/solid-openid-client`.
 *
 * The package wraps panva's `openid-client` v6 to perform the Solid-OIDC authorization-code +
 * PKCE + DPoP flow, composing `@jeswr/solid-dpop` for the RFC 9449 proof primitives. These types
 * describe the stable public surface; see `client.ts` for the engine and the README for usage.
 */

import type { DpopKeyPair } from "@jeswr/solid-dpop";

/** A DOM-compatible `fetch`. The authed `fetch` this package returns has this signature. */
export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/**
 * DPoP-bound tokens returned by the authorization-code exchange / a refresh. The DPoP private
 * key is NOT part of this object — it lives on the client handle, exposed as
 * `SolidOidcClient.dpopKeyPair` so you can persist it alongside the refresh token (the
 * refresh-token `jkt` binding requires the SAME key after a restart). Treat `accessToken` /
 * `refreshToken` / `idToken` (and the DPoP private key) as secrets; this package never logs them.
 */
export interface SolidOidcTokens {
  /** The DPoP-bound access token (`token_type: "DPoP"`). Present a DPoP proof with every use. */
  readonly accessToken: string;
  /** OAuth token type. For Solid-OIDC this is `"DPoP"` (sender-constrained). */
  readonly tokenType: string;
  /** Refresh token, present iff `offline_access` was granted. Persist this to refresh later. */
  readonly refreshToken?: string;
  /** The OIDC ID token (JWS). The `webid` claim is read from here (or the access token). */
  readonly idToken?: string;
  /** Seconds until the access token expires, as reported by the token endpoint. */
  readonly expiresIn?: number;
  /** Granted scopes (space-delimited), as reported by the token endpoint. */
  readonly scope?: string;
}

/** The result of a successful login: the authenticated WebID + the DPoP-bound tokens. */
export interface SolidOidcSession {
  /** The authenticated user's WebID, read from the `webid` claim (fail-closed if absent). */
  readonly webId: string;
  /** The issuer the tokens were obtained from. */
  readonly issuer: string;
  /** The DPoP-bound tokens. */
  readonly tokens: SolidOidcTokens;
}

/**
 * The transient state produced by {@link SolidOidcClient.authorizationUrl} that the caller MUST
 * carry to {@link SolidOidcClient.handleCallback} (in a server-side session, signed cookie, or
 * — for a CLI loopback flow — in-process). It contains the PKCE verifier, the random `state`,
 * and the random `nonce`. ALL THREE are secrets-for-the-flow: the PKCE verifier is the proof
 * the redirect came from this client; `state` is CSRF protection; `nonce` binds the ID token.
 */
export interface AuthorizationRequestState {
  /** PKCE code_verifier (S256). Sent to the token endpoint; never to the browser. */
  readonly codeVerifier: string;
  /** Random `state` echoed back on the redirect — validated to equal this exactly (CSRF). */
  readonly state: string;
  /** Random `nonce` — validated to equal the ID token `nonce` claim exactly. */
  readonly nonce: string;
  /** The redirect URI this request was built for; re-asserted at the token endpoint. */
  readonly redirectUri: string;
}

/** What {@link SolidOidcClient.authorizationUrl} returns. */
export interface AuthorizationRequest {
  /** The URL to redirect the user-agent to (or open in a browser for a CLI). */
  readonly url: string;
  /** The transient state to carry to {@link SolidOidcClient.handleCallback}. */
  readonly state: AuthorizationRequestState;
}

/**
 * Either the full authorization-response URL (preferred — `openid-client` extracts `code` /
 * `state` / `iss` / `error` from it) OR the already-parsed query params. Supplying the full URL
 * is the robust path because it lets the engine validate `iss` and surface `error` responses.
 */
export type CallbackInput =
  | { readonly url: string | URL }
  | { readonly params: Record<string, string> | URLSearchParams };

/**
 * A Client Identifier Document public client: a `clientId` that is an `https:` URL serving a
 * Solid client-id JSON-LD document. This is the PRIMARY, recommended path — the consent screen
 * shows a stable named client and there is no client secret to manage. (Dynamic client
 * registration is the documented secondary seam; see the README.)
 */
export interface ClientIdDocumentClient {
  /** An `https:` URL whose document is the app's Solid Client Identifier Document. */
  readonly clientId: string;
}

/**
 * A statically-known client (e.g. a pre-registered confidential or public client) supplying its
 * own `clientMetadata`. `clientId` is required; `clientSecret` only for a confidential client.
 */
export interface StaticClient {
  readonly clientId: string;
  readonly clientSecret?: string;
  /** Extra client metadata passed to `openid-client` discovery (e.g. `token_endpoint_auth_method`). */
  readonly clientMetadata?: Record<string, unknown>;
}

/** The client identity options: a Client ID Document client (preferred) or a static client. */
export type ClientIdentity = ClientIdDocumentClient | StaticClient;

/**
 * Options for {@link createSolidOidcClient}. `issuer` + `redirectUri` are always required; supply
 * EITHER `clientId` (a Client ID Document URL — the primary path) OR a full `client` identity.
 */
export interface CreateSolidOidcClientOptions {
  /** The Solid-OIDC issuer (OP) URL. Discovery hits `<issuer>/.well-known/openid-configuration`. */
  readonly issuer: string;
  /** The OAuth redirect URI registered for this client. */
  readonly redirectUri: string;
  /**
   * Shorthand for a Client ID Document public client: an `https:` URL serving the client-id doc.
   * Mutually exclusive with `client`.
   */
  readonly clientId?: string;
  /** Full client identity (Client ID Document or static). Mutually exclusive with `clientId`. */
  readonly client?: ClientIdentity;
  /**
   * Scopes to request. Defaults to `"openid webid offline_access"` (Solid-OIDC needs `webid`;
   * `offline_access` yields a refresh token). `openid` is forced on if omitted from a custom value.
   */
  readonly scope?: string;
  /**
   * An existing DPoP keypair to bind tokens to (e.g. restored from a persisted session so the
   * refresh-token `jkt` binding survives a restart). If omitted, a fresh ES256 keypair is
   * generated. Asymmetric-only (ES256) — enforced by `@jeswr/solid-dpop`.
   */
  readonly dpopKeyPair?: DpopKeyPair;
  /**
   * Inject a custom `fetch` for ALL HTTP the engine makes (discovery, token, resource). This is
   * the test seam (a Map-backed fake issuer) AND the place to wire an SSRF-guarded fetch in
   * production. Defaults to the global `fetch`.
   */
  readonly fetch?: FetchLike;
  /**
   * Allow `http:` (non-TLS) issuer/endpoint/resource URLs. OFF by default (Solid-OIDC requires
   * TLS). Only enable for a local dev OP / pod on loopback. When false, an `http:` issuer AND any
   * `http:` resource URL the authed `fetch` is asked to hit are rejected (so the DPoP token is
   * never sent over plaintext).
   */
  readonly allowInsecure?: boolean;
  /**
   * Cap (bytes) on a STREAM request body the authed `fetch` buffers for the §8 DPoP-nonce retry.
   * A stream body larger than this is rejected rather than buffered (memory-safety). Defaults to
   * 10 MiB. Non-stream bodies (string / Uint8Array / Blob / …) are already replayable and not
   * buffered, so the cap does not apply to them.
   */
  readonly maxReplayBodyBytes?: number;
}
