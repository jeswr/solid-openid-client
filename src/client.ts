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
 * Assert an issuer URL is https (or http-on-loopback only when `allowInsecure`). Mirrors the
 * RFC 8252 §8.3 / OAuth-BCP transport rule the suite uses elsewhere.
 */
function assertIssuerTransport(issuer: string, allowInsecure: boolean): void {
  let u: URL;
  try {
    u = new URL(issuer);
  } catch {
    throw new Error(`createSolidOidcClient: \`issuer\` is not a valid URL: ${issuer}`);
  }
  if (u.protocol === "https:") {
    return;
  }
  if (u.protocol === "http:") {
    const host = u.hostname;
    const isLoopback = host === "127.0.0.1" || host === "::1" || host === "localhost";
    if (allowInsecure && isLoopback) {
      return;
    }
    throw new Error(
      `createSolidOidcClient: refusing an insecure issuer (${issuer}). Solid-OIDC requires https; ` +
        "http: is permitted only for a loopback dev OP with `allowInsecure: true`.",
    );
  }
  throw new Error(
    `createSolidOidcClient: unsupported issuer scheme in ${issuer} (expected https:).`,
  );
}

/**
 * Read the `webid` claim — Solid-OIDC's WebID — from the token response, FAIL-CLOSED.
 *
 * Per the Solid-OIDC spec the WebID is advertised in the `webid` claim of the ID token (the
 * primary location) and, on most OPs, also in the access token. We read the ID token claims via
 * openid-client's verified `claims()` helper (it has already validated signature + `iss`/`aud`/
 * `nonce`), then fall back to a parsed access-token `webid`. If neither yields an `http(s)` WebID,
 * we THROW — a session is never returned without a resolvable WebID.
 */
function extractWebId(
  tokenResponse: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): string {
  // 1. Verified ID-token claims (preferred — signature/iss/aud/nonce already checked).
  const idClaims = tokenResponse.claims();
  const fromId = idClaims?.webid;
  if (typeof fromId === "string" && isHttpUri(fromId)) {
    return fromId;
  }

  // 2. Fall back to a `webid` claim in the access token (many Solid OPs put it there too). The
  //    access token's signature is the resource server's concern, not the client's — we only
  //    read the claim opportunistically and still require it to be an http(s) IRI.
  const fromAt = readAccessTokenWebId(tokenResponse.access_token);
  if (fromAt !== undefined && isHttpUri(fromAt)) {
    return fromAt;
  }

  throw new Error(
    "Solid-OIDC login produced no resolvable `webid` claim in the ID token or access token; " +
      "refusing to return a session without a WebID (fail-closed).",
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
 * Best-effort read of a `webid` claim from a JWT access token's payload WITHOUT verifying its
 * signature (the RS verifies the access token, not us). Returns `undefined` for a non-JWT
 * (opaque) access token or any parse failure. We do NOT trust this beyond cross-checking an
 * http(s) shape; the ID-token path above is the authoritative one.
 */
function readAccessTokenWebId(accessToken: string): string | undefined {
  const parts = accessToken.split(".");
  if (parts.length !== 3) {
    return undefined; // opaque / non-JWT access token
  }
  try {
    const payloadB64 = parts[1] as string;
    const json = Buffer.from(payloadB64, "base64url").toString("utf8");
    const payload = JSON.parse(json) as Record<string, unknown>;
    const webid = payload.webid;
    return typeof webid === "string" ? webid : undefined;
  } catch {
    return undefined;
  }
}

/** Map an openid-client token response into our public {@link SolidOidcTokens}. */
function toSolidTokens(
  res: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): SolidOidcTokens {
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
  const clientAuth = hasSecret(identity)
    ? oidc.ClientSecretPost(identity.clientSecret)
    : oidc.None();
  if (hasSecret(identity)) {
    baseMetadata.client_secret = identity.clientSecret;
  }

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
  const discoveredIssuer = config.serverMetadata().issuer;
  if (discoveredIssuer !== opts.issuer && discoveredIssuer !== stripTrailingSlash(opts.issuer)) {
    // Allow only the trailing-slash difference; anything else is an issuer-substitution attempt.
    if (stripTrailingSlash(discoveredIssuer) !== stripTrailingSlash(opts.issuer)) {
      throw new Error(
        `createSolidOidcClient: discovered issuer (${discoveredIssuer}) does not match the requested issuer (${opts.issuer}).`,
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
    const url = reqInput ? reqInput.url : input.toString();

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
      );
    } else if (reqInput && reqInput.body !== null) {
      // A Request body is a stream; read it (abort-aware, cancellable) so we can send it more
      // than once across the original + nonce retry.
      bufferedBody = await readStreamWithSignal(
        reqInput.clone().body as ReadableStream<Uint8Array>,
        effectiveSignal,
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

      const params: Record<string, string> = {
        redirect_uri: redirectUri,
        scope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
        ...(extraParams ?? {}),
      };
      const url = oidc.buildAuthorizationUrl(config, params);
      return {
        url: url.href,
        state: { codeVerifier, state, nonce, redirectUri },
      };
    },

    async handleCallback(callback, reqState) {
      const currentUrl = callbackToUrl(callback);
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
      const tokens = toSolidTokens(res);
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

/** Turn a {@link CallbackInput} into the `URL` openid-client expects. */
function callbackToUrl(callback: CallbackInput): URL {
  if ("url" in callback) {
    return callback.url instanceof URL ? callback.url : new URL(callback.url);
  }
  // Params form: openid-client needs a URL. The base origin is irrelevant for code-flow
  // extraction (only the query params matter), so we attach them to a placeholder URL. Using a
  // non-absolute placeholder is fine because authorizationCodeGrant only reads searchParams.
  const u = new URL("https://callback.invalid/");
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
 */
async function bufferBody(
  body: BodyInit | null | undefined,
  signal: AbortSignal | undefined,
): Promise<BodyInit | undefined> {
  if (body === null || body === undefined) {
    return undefined;
  }
  if (body instanceof ReadableStream) {
    return readStreamWithSignal(body, signal);
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
      chunks.push(result.value);
      total += result.value.byteLength;
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
