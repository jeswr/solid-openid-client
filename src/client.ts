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
import { bufferBody, DEFAULT_MAX_REPLAY_BODY_BYTES, readStreamWithSignal } from "./body-buffer.js";
import { generateDpopKeyPair, resourceDpopProof, toCryptoKeyPair } from "./dpop.js";
import { hasSecret, normalizeScope, resolveIdentity, selectClientAuth } from "./identity.js";
import {
  adaptCustomFetch,
  callbackToUrl,
  requestTransportFields,
  resolveUrl,
} from "./request-adapter.js";
import {
  assertIssuerTransport,
  assertRedirectUri,
  assertSecureTransport,
  stripTrailingSlash,
} from "./transport.js";
import type {
  AuthorizationRequest,
  AuthorizationRequestState,
  CallbackInput,
  CreateSolidOidcClientOptions,
  FetchLike,
  SolidOidcSession,
  SolidOidcTokens,
} from "./types.js";
import { extractWebId, extractWebIdOrUndefined, toSolidTokens } from "./webid.js";

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
  "dpop_jkt",
]);

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
  assertRedirectUri(redirectUri);
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
        // Drain the challenge response body before retrying so its connection/body resources are
        // released (we discard it — only the retry's response is returned). Best-effort.
        await res.body?.cancel().catch(() => {});
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
      // `dpop_jkt` binds the authorization CODE to our DPoP key (RFC 9449 §10): the thumbprint is
      // the suite keypair's (== the token `jkt`), so an OP that supports code binding ties the code
      // to the same key the token endpoint proves possession of. A roborev hardening finding.
      const params: Record<string, string> = {
        ...(extraParams ?? {}),
        redirect_uri: redirectUri,
        scope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
        dpop_jkt: dpopKeyPair.thumbprint,
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
      // Is this a refresh of the CURRENT session (same identity guaranteed) or with an EXPLICIT,
      // possibly-different token? An explicit token may belong to a different identity, so we must
      // not keep the prior `currentWebId` unless the refreshed ID token re-proves an identity.
      const sameSession =
        refreshTokenArg === undefined || refreshTokenArg === currentTokens?.refreshToken;

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

      // Re-derive the WebID from the refreshed VERIFIED ID token (same rules as login: `webid`
      // claim or `sub`). If the response carries one, adopt it. If it does NOT:
      //   - same-session refresh: keep the known WebID (identity is unchanged).
      //   - explicit (possibly different) token: CLEAR currentWebId — we must not report a stale
      //     identity that may not match the freshly-refreshed tokens (fail-closed; a roborev
      //     finding). Read currentWebId() again after re-login if you need it.
      const refreshedWebId = extractWebIdOrUndefined(res);
      if (refreshedWebId !== undefined) {
        currentWebId = refreshedWebId;
      } else if (!sameSession) {
        currentWebId = undefined;
      }
      return tokens;
    },
  };
}
