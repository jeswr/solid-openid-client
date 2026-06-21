// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
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
import * as oidc from "openid-client";
import { generateDpopKeyPair, resourceDpopProof, toCryptoKeyPair } from "./dpop.js";
import type {
  AuthorizationRequest,
  AuthorizationRequestState,
  CallbackInput,
  ClientIdentity,
  CreateSolidOidcClientOptions,
  FetchLike,
  SolidOidcSession,
  SolidOidcTokens,
} from "./types.js";

/** Default scopes. `webid` is Solid-OIDC's WebID scope; `offline_access` yields a refresh token. */
export const DEFAULT_SCOPE = "openid webid offline_access";

/**
 * Default cap (bytes) on a STREAM request body buffered for §8 nonce-retry replay. A stream body
 * larger than this is rejected rather than buffered (so an upload cannot exhaust memory). 10 MiB —
 * generous for typical Solid resource writes; raise via `maxReplayBodyBytes` for larger uploads.
 */
export const DEFAULT_MAX_REPLAY_BODY_BYTES = 10 * 1024 * 1024;

/**
 * Authorization-request parameters the engine OWNS — a caller's `extraParams` must not override
 * these, because the package's PKCE / state / nonce / scope guarantees depend on them. An attempt
 * to set any of these via `extraParams` is rejected.
 */
const RESERVED_AUTH_PARAMS = new Set([
  "client_id",
  "redirect_uri",
  "scope",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce",
]);

/**
 * Force `openid` into a scope string (OIDC requires it) and de-duplicate. Order otherwise
 * preserved. An empty / whitespace input falls back to {@link DEFAULT_SCOPE}.
 */
function normalizeScope(scope: string | undefined): string {
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
function resolveIdentity(opts: CreateSolidOidcClientOptions): ClientIdentity {
  if (opts.client !== undefined && opts.clientId !== undefined) {
    throw new Error(
      "createSolidOidcClient: supply EITHER `clientId` (a Client ID Document URL) OR `client`, not both.",
    );
  }
  if (opts.client !== undefined) {
    return opts.client;
  }
  if (opts.clientId !== undefined) {
    return { clientId: opts.clientId };
  }
  throw new Error(
    "createSolidOidcClient: a client identity is required — pass `clientId` (a Client ID Document URL, the primary path) or a full `client`.",
  );
}

/** True iff the identity carries a confidential client secret. */
function hasSecret(id: ClientIdentity): id is ClientIdentity & { clientSecret: string } {
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
function selectClientAuth(
  identity: ClientIdentity,
  tokenEndpointAuthMethod: string | undefined,
): oidc.ClientAuth {
  if (!hasSecret(identity)) {
    return oidc.None();
  }
  const secret = identity.clientSecret;
  switch (tokenEndpointAuthMethod) {
    case "client_secret_basic":
      return oidc.ClientSecretBasic(secret);
    case "none":
      return oidc.None();
    case "client_secret_jwt":
      return oidc.ClientSecretJwt(secret);
    default:
      // client_secret_post (the default) or an unrecognised value → POST.
      return oidc.ClientSecretPost(secret);
  }
}

/**
 * True iff `hostname` (as returned by `URL.hostname`) is a loopback host. Handles `localhost`, the
 * whole `127.0.0.0/8` IPv4 loopback range, and IPv6 `::1` — including Node's BRACKETED IPv6 form
 * (`URL.hostname` returns `[::1]` with brackets, so a bare `=== "::1"` check would miss it).
 */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost") {
    return true;
  }
  // IPv6 loopback — strip the brackets URL.hostname adds, then compare. `::1` and its expanded
  // forms all normalise to `::1` via URL parsing, but compare defensively.
  const unbracketed = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (unbracketed === "::1") {
    return true;
  }
  // IPv4 127.0.0.0/8.
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(unbracketed)) {
    const octets = unbracketed.split(".").map(Number);
    return octets.every((o) => o >= 0 && o <= 255);
  }
  return false;
}

/**
 * Assert a URL is https (or http-on-loopback only when `allowInsecure`). Mirrors the RFC 8252
 * §8.3 / OAuth-BCP transport rule the suite uses elsewhere. `label`/`makeError` shape the message.
 */
function assertSecureTransport(
  rawUrl: string,
  allowInsecure: boolean,
  makeError: (msg: string) => Error,
): void {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw makeError(`not a valid URL: ${rawUrl}`);
  }
  if (u.protocol === "https:") {
    return;
  }
  if (u.protocol === "http:") {
    if (allowInsecure && isLoopbackHost(u.hostname)) {
      return;
    }
    throw makeError(
      `refusing an insecure http: URL (${rawUrl}). https is required; http: is permitted only for a ` +
        "loopback host with `allowInsecure: true`.",
    );
  }
  throw makeError(`unsupported URL scheme in ${rawUrl} (expected https:).`);
}

/** Assert an issuer URL is https (or http-on-loopback only when `allowInsecure`). */
function assertIssuerTransport(issuer: string, allowInsecure: boolean): void {
  assertSecureTransport(issuer, allowInsecure, (msg) => new Error(`createSolidOidcClient: ${msg}`));
}

/**
 * Assert the redirect URI is a valid absolute URL, on a secure transport, with NO query/fragment.
 *
 * - Transport: https (or http on a loopback host only when `allowInsecure`) — same rule as the
 *   issuer/endpoints, so an authorization code is never delivered over plaintext to a real host (a
 *   roborev finding).
 * - No query/fragment: openid-client v6 derives the token-endpoint `redirect_uri` from the callback
 *   URL's origin+path (query stripped), so a registered redirect URI carrying its own query — e.g.
 *   `https://app.example/callback?tenant=a` — would be sent to the OP as `.../callback`, a mismatch
 *   the OP rejects. We reject it up front with a clear error; carry per-flow data in
 *   `state`/`extraParams`, not the redirect URI's query.
 */
function assertRedirectUri(redirectUri: string, allowInsecure: boolean): void {
  let u: URL;
  try {
    u = new URL(redirectUri);
  } catch {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` is not a valid absolute URL: ${redirectUri}`,
    );
  }
  assertSecureTransport(
    redirectUri,
    allowInsecure,
    (msg) => new Error(`createSolidOidcClient: \`redirectUri\` ${msg}`),
  );
  if (u.search !== "" || u.hash !== "") {
    throw new Error(
      `createSolidOidcClient: \`redirectUri\` must not contain a query string or fragment (${redirectUri}). ` +
        "openid-client derives the token-endpoint redirect_uri from the callback origin+path (query " +
        "stripped), so a query here would mismatch and the OP would reject the code exchange. Carry " +
        "per-flow data in `state` / `authorizationUrl(extraParams)` instead.",
    );
  }
}

/**
 * Resolve a string/URL `fetch` input to an absolute URL string, the way browser `fetch` does: a
 * relative URL is resolved against the document base when present (a browser/worker), else it must
 * be absolute (server-side Node has no base — a relative URL throws a clear error). This keeps the
 * authed `fetch` a drop-in for the DOM `fetch` in a browser context while staying strict
 * server-side.
 *
 * The base is `document.baseURI` (which honours a `<base href>`) when in a document context —
 * matching native `fetch` exactly — falling back to `location.href` for a worker-like context.
 */
function resolveUrl(input: string | URL): string {
  if (input instanceof URL) {
    return input.toString();
  }
  const g = globalThis as {
    document?: { baseURI?: string };
    location?: { href?: string };
  };
  const base = g.document?.baseURI ?? g.location?.href;
  try {
    return base !== undefined ? new URL(input, base).toString() : new URL(input).toString();
  } catch {
    throw new Error(
      `authedFetch: \`${input}\` is not an absolute URL and there is no document base to resolve it ` +
        "against (server-side). Pass an absolute https URL.",
    );
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
function extractWebId(
  tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): string {
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

  throw new Error(
    "Solid-OIDC login produced no resolvable `webid` claim in the VERIFIED ID token; refusing to " +
      "return a session without a verified WebID (fail-closed). The WebID is never trusted from an " +
      "unverified access token.",
  );
}

/** True iff `value` parses as an http(s) URL. WebIDs MUST be dereferenceable http(s) IRIs. */
function isHttpUri(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
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
function toSolidTokens(
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

/**
 * The Solid-OIDC client handle returned by {@link createSolidOidcClient}. Stateful only insofar
 * as it holds the discovered configuration, the DPoP keypair, and (after a login/refresh) the
 * latest tokens — the consumer owns persistence (token storage is an injectable seam: persist
 * `currentTokens()` + the `dpopKeyPair` yourself).
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
  handleCallback(
    callback: CallbackInput,
    state: AuthorizationRequestState,
  ): Promise<SolidOidcSession>;
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
export async function createSolidOidcClient(
  opts: CreateSolidOidcClientOptions,
): Promise<SolidOidcClient> {
  const allowInsecure = opts.allowInsecure === true;
  assertIssuerTransport(opts.issuer, allowInsecure);

  const identity = resolveIdentity(opts);
  const scope = normalizeScope(opts.scope);
  const redirectUri = opts.redirectUri;
  assertRedirectUri(redirectUri, allowInsecure);
  const maxReplayBodyBytes = opts.maxReplayBodyBytes ?? DEFAULT_MAX_REPLAY_BODY_BYTES;
  // The consumer's DOM-shaped fetch (test seam / SSRF-guarded fetch in prod). Used directly for
  // the resource-leg authed fetch, and adapted to openid-client's `CustomFetch` for discovery /
  // token requests.
  const userFetch: FetchLike = opts.fetch ?? (globalThis.fetch as FetchLike);

  // DPoP keypair: reuse a supplied one (restored session) or generate a fresh ES256 one.
  // `@jeswr/solid-dpop` owns the algorithm/extractable/thumbprint policy.
  const dpopKeyPair: DpopKeyPair = opts.dpopKeyPair ?? (await generateDpopKeyPair());

  // Client metadata for openid-client: a public client (Client ID Document) carries no secret;
  // a confidential static client supplies one. We always pin `redirect_uris` so the engine can
  // validate the redirect, and merge any caller-supplied metadata.
  const baseMetadata: Partial<oidc.ClientMetadata> = {
    client_id: identity.clientId,
    redirect_uris: [redirectUri],
    ...(("clientMetadata" in identity && identity.clientMetadata) || {}),
  };
  if (hasSecret(identity)) {
    baseMetadata.client_secret = identity.clientSecret;
  }
  // Client authentication method: a confidential client honours its
  // `clientMetadata.token_endpoint_auth_method` (so a client registered for `client_secret_basic`
  // works, not only `client_secret_post`; a roborev finding); default for a confidential client is
  // `client_secret_post`. A public client (no secret) uses `none`.
  const authMethod = baseMetadata.token_endpoint_auth_method;
  const clientAuth = selectClientAuth(
    identity,
    typeof authMethod === "string" ? authMethod : undefined,
  );

  // Discovery — inject the custom fetch (test seam / SSRF-guarded fetch in prod) and, for a
  // loopback dev OP, allow insecure requests. openid-client's `CustomFetch` has a narrower
  // options shape (`CustomFetchOptions`) than DOM `fetch`; `adaptCustomFetch` bridges them.
  const discoveryOptions: oidc.DiscoveryRequestOptions = {
    [oidc.customFetch]: adaptCustomFetch(userFetch),
    ...(allowInsecure ? { execute: [oidc.allowInsecureRequests] } : {}),
  };

  const config = await oidc.discovery(
    new URL(opts.issuer),
    identity.clientId,
    baseMetadata,
    clientAuth,
    discoveryOptions,
  );

  // The issuer reported by the OP must equal the requested issuer exactly (OIDC Discovery §4.3).
  const serverMetadata = config.serverMetadata();
  const discoveredIssuer = serverMetadata.issuer;
  if (discoveredIssuer !== opts.issuer && discoveredIssuer !== stripTrailingSlash(opts.issuer)) {
    // Allow only the trailing-slash difference; anything else is an issuer-substitution attempt.
    if (stripTrailingSlash(discoveredIssuer) !== stripTrailingSlash(opts.issuer)) {
      throw new Error(
        `createSolidOidcClient: discovered issuer (${discoveredIssuer}) does not match the requested issuer (${opts.issuer}).`,
      );
    }
  }

  // SECURITY: when `allowInsecure` enables http: for a loopback dev OP, openid-client's
  // `allowInsecureRequests` disables TLS enforcement for ALL endpoints — so a (loopback) discovery
  // document could advertise an `http://non-loopback/token` and leak the code/token over plaintext
  // to an arbitrary host. Re-apply the same https-or-loopback rule to EVERY endpoint we will
  // actually contact, after discovery (a roborev finding). With `allowInsecure` off, openid-client
  // already enforces https, but we check anyway (defense-in-depth, zero cost).
  for (const [name, endpoint] of [
    ["authorization_endpoint", serverMetadata.authorization_endpoint],
    ["token_endpoint", serverMetadata.token_endpoint],
    ["jwks_uri", serverMetadata.jwks_uri],
  ] as const) {
    if (typeof endpoint === "string" && endpoint.length > 0) {
      assertSecureTransport(
        endpoint,
        allowInsecure,
        (msg) =>
          new Error(
            `createSolidOidcClient: discovered ${name} ${msg} (refusing an insecure endpoint).`,
          ),
      );
    }
  }

  // openid-client DPoP handle, bound to the SAME suite keypair (its thumbprint == the `jkt`).
  // openid-client signs the token-endpoint proofs + tracks server nonces (RFC 9449 §8) with it.
  const dpopHandle = oidc.getDPoPHandle(config, toCryptoKeyPair(dpopKeyPair) as oidc.CryptoKeyPair);

  let currentTokens: SolidOidcTokens | undefined;
  let currentWebId: string | undefined;

  // The DPoP-attaching authed fetch. Builds the resource-request proof via @jeswr/solid-dpop
  // (with `ath` bound to the current access token) and retries once on a server `DPoP-Nonce`
  // challenge (RFC 9449 §8). Throws if called before any token is available.
  //
  // It handles a `Request` input AND an `init` faithfully: the effective method/headers/body are
  // resolved from BOTH (an explicit `init` field overrides the `Request`'s), so a `POST`/`PUT`
  // `Request` passed with no `init` keeps its method + body (a bug fixed per a roborev finding).
  // The body is BUFFERED once up front (to a string/ArrayBuffer) so the §8 nonce retry can replay
  // it — a non-replayable stream body would otherwise be consumed by the first attempt.
  const authedFetch: FetchLike = async (input, init) => {
    if (currentTokens === undefined) {
      throw new Error(
        "authedFetch: no access token yet — call handleCallback()/refresh() before fetching.",
      );
    }
    const accessToken = currentTokens.accessToken;
    const reqInput = input instanceof Request ? input : undefined;
    // A `Request` always carries an absolute `.url`. A string/URL input may be RELATIVE (browser
    // `fetch` resolves it against the document base); resolve it the same way so we don't reject a
    // valid relative URL — and so the transport check + `htu` + the fetch all use one absolute URL.
    const url = input instanceof Request ? input.url : resolveUrl(input);

    // SECURITY: never attach the DPoP access token + proof to a plaintext URL — that would leak the
    // bearer-class token over the wire. Require https (http only on loopback when allowInsecure),
    // BEFORE building any header/proof (a roborev finding).
    assertSecureTransport(
      url,
      allowInsecure,
      (msg) => new Error(`authedFetch: ${msg} — refusing to send the DPoP token over plaintext.`),
    );

    // Effective method: explicit init wins, else the Request's, else GET.
    const method = (init?.method ?? reqInput?.method ?? "GET").toUpperCase();

    // Effective base RequestInit, carrying over ALL relevant transport fields from the Request
    // first, then letting an explicit init override them, so nothing (mode/credentials/cache/
    // redirect/integrity/keepalive/referrer/referrerPolicy/signal/…) is silently dropped when we
    // replace the original `Request` with `userFetch(url, init)`.
    const baseInit: RequestInit = {
      ...(reqInput ? requestTransportFields(reqInput) : {}),
      ...(init ?? {}),
      method,
    };
    // `body` is owned by the buffering logic below — never leak the original (possibly already
    // consumed) stream from baseInit into the per-attempt RequestInit.
    delete (baseInit as { body?: unknown }).body;

    // The effective abort signal (explicit init wins, else the Request's). It is honoured both
    // while BUFFERING a stream body (so an abort during the read rejects promptly instead of
    // draining the stream) and is carried into the per-attempt RequestInit via baseInit.
    const effectiveSignal: AbortSignal | undefined =
      init && "signal" in init ? (init.signal ?? undefined) : (reqInput?.signal ?? undefined);

    // Buffer the body ONCE so it is REPLAYABLE across the original + nonce-retry attempts — a
    // non-replayable stream (a `Request` body, or a `ReadableStream` passed via init.body) would
    // otherwise be consumed by the first attempt and the §8 retry would send an empty/locked body.
    // Precedence matches `fetch`: an explicit `init.body` wins over the Request's body.
    let bufferedBody: BodyInit | undefined;
    if (init && "body" in init) {
      bufferedBody = await bufferBody(
        (init.body ?? undefined) as BodyInit | null | undefined,
        effectiveSignal,
        maxReplayBodyBytes,
      );
    } else if (reqInput && reqInput.body !== null) {
      // A Request body is a stream; read it (abort-aware, cancellable, size-capped) so we can send
      // it more than once across the original + nonce retry.
      bufferedBody = await readStreamWithSignal(
        reqInput.clone().body as ReadableStream<Uint8Array>,
        effectiveSignal,
        maxReplayBodyBytes,
      );
    }

    // Merge headers from the Request then the init (init overrides), so a Request's content-type
    // etc. is preserved while an explicit init header still wins.
    const buildHeaders = (proof: string): Headers => {
      const headers = new Headers(reqInput?.headers ?? undefined);
      if (init?.headers) {
        new Headers(init.headers).forEach((v, k) => {
          headers.set(k, v);
        });
      }
      headers.set("authorization", `DPoP ${accessToken}`);
      headers.set("dpop", proof);
      return headers;
    };

    const doFetch = async (nonce?: string): Promise<Response> => {
      const proof = await resourceDpopProof(dpopKeyPair, method, url, accessToken, nonce);
      const req: RequestInit = {
        ...baseInit,
        headers: buildHeaders(proof),
        ...(bufferedBody !== undefined ? { body: bufferedBody } : {}),
      };
      return userFetch(url, req);
    };

    const res = await doFetch();
    // §8 nonce challenge: a 401 with a `DPoP-Nonce` header → retry once echoing the nonce.
    if (res.status === 401) {
      const serverNonce = res.headers.get("dpop-nonce");
      if (serverNonce) {
        return doFetch(serverNonce);
      }
    }
    return res;
  };

  return {
    issuer: opts.issuer,
    dpopKeyPair,
    fetch: authedFetch,
    currentTokens: () => currentTokens,
    currentWebId: () => currentWebId,

    async authorizationUrl(extraParams) {
      // PKCE S256 — ALWAYS. state + nonce — ALWAYS (CSRF + ID-token binding).
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();

      // Reserved parameters are OWNED by the engine — a caller MUST NOT override the
      // security-critical values (the "always generated/validated" guarantee). We reject any
      // attempt rather than silently ignore it, so a mistaken override is loud, not a downgrade.
      if (extraParams) {
        const overridden = Object.keys(extraParams).filter((k) => RESERVED_AUTH_PARAMS.has(k));
        if (overridden.length > 0) {
          throw new Error(
            `authorizationUrl: extraParams must not override reserved parameter(s): ${overridden.join(", ")}. ` +
              "These (PKCE, state, nonce, scope, response_type, redirect_uri, client_id) are generated by the engine.",
          );
        }
      }

      // extraParams spread FIRST so the generated security params always win even if the reserved
      // guard above is ever bypassed (defense-in-depth).
      const params: Record<string, string> = {
        ...(extraParams ?? {}),
        redirect_uri: redirectUri,
        scope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
      };
      const url = oidc.buildAuthorizationUrl(config, params);
      return {
        url: url.href,
        state: { codeVerifier, state, nonce, redirectUri },
      };
    },

    async handleCallback(callback, reqState) {
      const currentUrl = callbackToUrl(callback, reqState.redirectUri);
      const tokenResponse = await oidc.authorizationCodeGrant(
        config,
        currentUrl,
        {
          pkceCodeVerifier: reqState.codeVerifier,
          expectedState: reqState.state, // exact-match CSRF check (openid-client throws on mismatch)
          expectedNonce: reqState.nonce, // exact-match ID-token nonce check
          idTokenExpected: true, // a Solid-OIDC login MUST return an ID token
        },
        undefined,
        { DPoP: dpopHandle },
      );

      const webId = extractWebId(tokenResponse);
      const tokens = toSolidTokens(tokenResponse);
      currentTokens = tokens;
      currentWebId = webId;
      return { webId, issuer: opts.issuer, tokens };
    },

    async refresh(refreshTokenArg) {
      const refreshToken = refreshTokenArg ?? currentTokens?.refreshToken;
      if (refreshToken === undefined) {
        throw new Error(
          "refresh: no refresh token available — supply one or log in with `offline_access` first.",
        );
      }
      const res = await oidc.refreshTokenGrant(config, refreshToken, undefined, {
        DPoP: dpopHandle,
      });
      let tokens = toSolidTokens(res);
      // An OP that does NOT rotate the refresh token omits `refresh_token` from the response. In
      // that case the PRIOR refresh token (the one we just used) is still valid — carry it forward
      // so the next refresh() does not fail with "no refresh token". A rotated token still wins.
      if (tokens.refreshToken === undefined) {
        tokens = { ...tokens, refreshToken };
      }
      currentTokens = tokens;
      // A refresh response may carry an updated ID token with the webid; keep currentWebId fresh
      // when one is present, but never clobber a known WebID with nothing.
      const refreshedWebId = res.claims()?.webid;
      if (typeof refreshedWebId === "string" && isHttpUri(refreshedWebId)) {
        currentWebId = refreshedWebId;
      }
      return tokens;
    },
  };
}

/**
 * Turn a {@link CallbackInput} into the `URL` openid-client expects, with the params-form URL built
 * on the REGISTERED `redirectUri`.
 *
 * openid-client v6 derives the `redirect_uri` it sends to the token endpoint from this URL's
 * origin+path. The params form must therefore be assembled on the real `redirectUri` base (NOT a
 * placeholder), otherwise the OP receives a mismatched/invalid `redirect_uri` and rejects the code
 * exchange (a roborev finding). For the `url` form the caller already supplies the full callback
 * URL (which is the redirect URI + the response params), so we use it as-is.
 */
function callbackToUrl(callback: CallbackInput, redirectUri: string): URL {
  if ("url" in callback) {
    return callback.url instanceof URL ? callback.url : new URL(callback.url);
  }
  // Params form: build the URL on the registered redirect URI so the derived redirect_uri is
  // correct. Append the response params to whatever query the redirect URI already carries.
  const u = new URL(redirectUri);
  const params =
    callback.params instanceof URLSearchParams
      ? callback.params
      : new URLSearchParams(callback.params);
  for (const [k, v] of params) {
    u.searchParams.set(k, v);
  }
  return u;
}

function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

/**
 * Extract the transport-relevant fields of a `Request` into a `RequestInit`, so replacing the
 * Request with `userFetch(url, init)` does not silently drop fetch semantics (credentials, mode,
 * cache, redirect, integrity, keepalive, referrer, referrerPolicy, signal). `body`/`method`/
 * `headers` are handled separately by the authed-fetch buffering + header-merge logic.
 */
function requestTransportFields(req: Request): RequestInit {
  return {
    method: req.method,
    redirect: req.redirect,
    cache: req.cache,
    credentials: req.credentials,
    integrity: req.integrity,
    keepalive: req.keepalive,
    mode: req.mode,
    referrer: req.referrer,
    referrerPolicy: req.referrerPolicy,
    ...(req.signal ? { signal: req.signal } : {}),
  };
}

/**
 * Buffer a body into a REPLAYABLE form. A `ReadableStream` is read once into an `ArrayBuffer` so
 * it can be sent on both the original attempt and the §8 nonce retry; all other `BodyInit` values
 * (string / `Uint8Array` / `Blob` / `URLSearchParams` / `FormData` / `ArrayBuffer`) are already
 * replayable and pass through unchanged. `null`/`undefined` → `undefined`. An `AbortSignal`, when
 * supplied, aborts an in-flight stream read promptly (matching `fetch` abort semantics).
 *
 * `maxBytes` caps the buffered size so a large/unbounded stream upload cannot exhaust memory (a
 * roborev finding): a stream body larger than the cap is REJECTED rather than buffered. To upload a
 * body larger than the cap, raise `maxReplayBodyBytes` (or pass a non-stream body, which is not
 * buffered).
 */
async function bufferBody(
  body: BodyInit | null | undefined,
  signal: AbortSignal | undefined,
  maxBytes: number,
): Promise<BodyInit | undefined> {
  if (body === null || body === undefined) {
    return undefined;
  }
  if (body instanceof ReadableStream) {
    return readStreamWithSignal(body, signal, maxBytes);
  }
  return body;
}

/**
 * Drain a `ReadableStream<Uint8Array>` to a single `Uint8Array`, honouring an optional
 * `AbortSignal`. We read MANUALLY via `stream.getReader()` (NOT `new Response(stream).arrayBuffer()`)
 * because `arrayBuffer()` locks the stream's reader, after which `stream.cancel()` throws and the
 * in-flight read is NOT cancelled — a never-ending stream would keep draining in the background
 * even after our promise rejected (a roborev finding). With our own reader we can `reader.cancel()`
 * on abort, which actually stops the active read. Each `reader.read()` is raced against the abort
 * so an abort mid-chunk rejects promptly.
 */
async function readStreamWithSignal(
  stream: ReadableStream<Uint8Array>,
  signal: AbortSignal | undefined,
  maxBytes: number,
): Promise<ArrayBuffer> {
  const reader = stream.getReader();

  // ONE abort listener for the whole read (not one per chunk). `abortRace` is a single promise
  // that rejects when the signal fires; it is reused across every `reader.read()`. The listener is
  // removed in the `finally` below, so a long multi-chunk read does not accumulate stale listeners
  // (a roborev finding).
  let removeAbortListener: (() => void) | undefined;
  const abortRace: Promise<never> | undefined =
    signal === undefined
      ? undefined
      : new Promise<never>((_resolve, reject) => {
          const onAbort = () => reject(abortReason(signal));
          signal.addEventListener("abort", onAbort, { once: true });
          removeAbortListener = () => signal.removeEventListener("abort", onAbort);
        });
  // Swallow the abortRace rejection if it never wins the race (avoids an unhandled rejection when
  // the read completes first and we stop awaiting it).
  abortRace?.catch(() => {});

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    // Route the already-aborted case through the same try/finally so the lock is always released.
    if (signal?.aborted) {
      throw abortReason(signal);
    }
    for (;;) {
      const result = abortRace
        ? await Promise.race([reader.read(), abortRace])
        : await reader.read();
      if (result.done) {
        break;
      }
      total += result.value.byteLength;
      // Bounded buffering: a body larger than the cap is rejected (cancels the reader) rather than
      // buffered, so a large/unbounded upload cannot exhaust memory.
      if (total > maxBytes) {
        throw new Error(
          `authedFetch: request stream body exceeds the ${maxBytes}-byte replay buffer cap. ` +
            "Raise `maxReplayBodyBytes` to upload a larger body (it is buffered so the §8 DPoP-nonce " +
            "retry can replay it).",
        );
      }
      chunks.push(result.value);
    }
  } catch (err) {
    // On abort (or any read error) cancel the reader so the source stops producing, then rethrow.
    await reader.cancel(err).catch(() => {});
    throw err;
  } finally {
    removeAbortListener?.();
    reader.releaseLock();
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  // Return an ArrayBuffer (a `BodyInit`/`BufferSource`) sized exactly to the bytes read.
  return out.buffer.slice(0, total);
}

/** The abort reason if the signal supplies one, else a standard `AbortError`. */
function abortReason(signal: AbortSignal): unknown {
  const reason = (signal as { reason?: unknown }).reason;
  if (reason !== undefined) {
    return reason;
  }
  return new DOMException("The operation was aborted.", "AbortError");
}

/**
 * Adapt a DOM-shaped {@link FetchLike} into openid-client's `CustomFetch`
 * (`(url, CustomFetchOptions) => Promise<Response>`). `CustomFetchOptions` is structurally a
 * subset of `RequestInit` (`body`/`headers`/`method`/`redirect`/`signal`), so it forwards
 * directly. We preserve openid-client's `redirect: "manual"` (it relies on inspecting redirects
 * itself, not following them) and pass through the abort `signal`.
 */
function adaptCustomFetch(userFetch: FetchLike): oidc.CustomFetch {
  return (url, options) => {
    const init: RequestInit = {
      method: options.method,
      headers: options.headers,
      redirect: options.redirect,
      ...(options.body !== undefined ? { body: options.body as BodyInit } : {}),
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
    };
    return userFetch(url, init);
  };
}
