// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * A Map-backed fake Solid-OIDC Provider for the test suite — NO live IdP, NO network, NO ports.
 *
 * It is deliberately FAITHFUL where the security tests depend on it: the ID token is a REAL
 * ES256-signed JWS minted by `jose`, the discovery doc advertises a real `jwks_uri`, and the
 * authorization endpoint records the PKCE `code_challenge` so the token endpoint can verify the
 * `code_verifier` (S256) — exactly as a real OP does. This is what makes the tests non-vacuous:
 * `openid-client` actually validates the ID token signature / `iss` / `aud` / `nonce` against
 * this OP, and our PKCE-mismatch test fails because the OP genuinely rejects a bad verifier.
 *
 * The fake `fetch` it produces is injected via `createSolidOidcClient({ fetch })` and into
 * `openid-client`'s discovery (`customFetch`). It also doubles as the resource-server stub so the
 * authed-fetch test can assert the DPoP proof (with `ath`) that arrives on a resource request.
 */

import { createHash } from "node:crypto";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type JWK,
  jwtVerify,
  SignJWT,
} from "jose";

/** A request the fake OP / RS captured, for assertions. */
export interface CapturedRequest {
  readonly url: string;
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body?: string;
}

export interface MockOpOptions {
  /** The issuer identifier (e.g. "https://op.example/"). */
  readonly issuer: string;
  /** The client_id the OP will mint `aud` for. */
  readonly clientId: string;
  /** The WebID to put in the `webid` claim of the ID token. Omit to mint NO webid claim. */
  readonly webId?: string | undefined;
  /** Put the `webid` claim into the access token (a JWS) instead of / in addition to the ID token. */
  readonly webIdInAccessToken?: string | undefined;
  /** Issue an opaque (non-JWT) access token instead of a signed JWS. */
  readonly opaqueAccessToken?: boolean;
  /** Omit the ID token entirely from the token response (to test fail-closed). */
  readonly omitIdToken?: boolean;
  /** Grant a refresh token (offline_access). Default true. */
  readonly grantRefreshToken?: boolean;
}

export interface MockOp {
  /** The fake `fetch` to inject everywhere (discovery, token, resource). */
  readonly fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  /** Drive the authorization endpoint: returns the redirect `code` + echoed `state`. */
  authorize(authUrl: string): { code: string; state: string };
  /** Every request the OP / RS captured (for assertions, e.g. the resource DPoP proof). */
  readonly captured: CapturedRequest[];
  /** The OP signing public JWK (for cross-checks). */
  readonly opPublicJwk: JWK;
  /** Force the NEXT token-endpoint call to issue a DIFFERENT access token (refresh round-trip). */
  rotateAccessToken(): void;
  /** Force the NEXT resource request to answer 401 with a `DPoP-Nonce` (the §8 challenge). */
  challengeNextResourceWithNonce(nonce: string): void;
  /** The most recent resource-request DPoP proof header captured (decoded), if any. */
  lastResourceDpop():
    | { header: Record<string, unknown>; payload: Record<string, unknown> }
    | undefined;
}

interface AuthRecord {
  readonly codeChallenge: string;
  readonly nonce: string;
  readonly state: string;
  readonly redirectUri: string;
}

function b64urlJson(obj: unknown): Record<string, unknown> {
  return obj as Record<string, unknown>;
}

function decodeJwtPart(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
}

function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/**
 * Build a mock OP. `setup()` must be awaited (it generates the OP signing key). Returns a handle
 * whose `fetch` faithfully answers discovery / jwks / token / resource requests.
 */
export async function createMockOp(opts: MockOpOptions): Promise<MockOp> {
  const issuer = opts.issuer;
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
  const grantRefreshToken = opts.grantRefreshToken !== false;

  // OP signing keypair (ES256) — the ID token is signed with this; openid-client validates it
  // against the JWKS we serve.
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const opPublicJwk = await exportJWK(publicKey);
  opPublicJwk.kid = "op-key-1";
  opPublicJwk.alg = "ES256";
  opPublicJwk.use = "sig";

  const authCodes = new Map<string, AuthRecord>();
  const captured: CapturedRequest[] = [];
  let accessTokenCounter = 0;
  let nextResourceNonce: string | undefined;
  let lastResourceProof:
    | { header: Record<string, unknown>; payload: Record<string, unknown> }
    | undefined;

  const discoveryDoc = {
    issuer,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    jwks_uri: `${base}/jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["ES256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["openid", "webid", "offline_access"],
    dpop_signing_alg_values_supported: ["ES256"],
  };

  async function mintIdToken(nonce: string, webId: string | undefined): Promise<string> {
    const payload: Record<string, unknown> = {
      sub: "the-subject",
      nonce,
    };
    if (webId !== undefined) {
      payload.webid = webId;
    }
    return new SignJWT(b64urlJson(payload))
      .setProtectedHeader({ alg: "ES256", kid: "op-key-1", typ: "JWT" })
      .setIssuer(issuer)
      .setAudience(opts.clientId)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(privateKey);
  }

  async function mintAccessToken(): Promise<string> {
    accessTokenCounter += 1;
    if (opts.opaqueAccessToken) {
      return `opaque-access-token-${accessTokenCounter}`;
    }
    const payload: Record<string, unknown> = {
      sub: "the-subject",
      // a numeric counter inside the JWS so a rotated token is a genuinely different string
      atc: accessTokenCounter,
    };
    if (opts.webIdInAccessToken !== undefined) {
      payload.webid = opts.webIdInAccessToken;
    }
    return new SignJWT(b64urlJson(payload))
      .setProtectedHeader({ alg: "ES256", kid: "op-key-1", typ: "at+jwt" })
      .setIssuer(issuer)
      .setAudience("solid")
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(privateKey);
  }

  async function handle(url: string, init: RequestInit | undefined): Promise<Response> {
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = normalizeHeaders(init?.headers);
    const body = await readBody(init?.body);
    captured.push(body !== undefined ? { url, method, headers, body } : { url, method, headers });

    const u = new URL(url);
    const path = u.pathname.replace(/\/+$/, "") || "/";

    // --- Discovery ---
    if (
      url === `${base}/.well-known/openid-configuration` ||
      path === "/.well-known/openid-configuration"
    ) {
      return json(discoveryDoc);
    }
    // --- JWKS ---
    if (path === "/jwks") {
      return json({ keys: [opPublicJwk] });
    }
    // --- Token endpoint ---
    if (path === "/token" && method === "POST") {
      return tokenEndpoint(body, headers);
    }
    // --- Resource server (any other path under the issuer base) ---
    return resourceEndpoint(url, method, headers);
  }

  async function tokenEndpoint(
    body: string | undefined,
    headers: Record<string, string>,
  ): Promise<Response> {
    const params = new URLSearchParams(body ?? "");
    const grantType = params.get("grant_type");

    // A DPoP proof on the token endpoint is required for a sender-constrained token. Capture it.
    const tokenDpop = headers.dpop;

    if (grantType === "authorization_code") {
      const code = params.get("code") ?? "";
      const verifier = params.get("code_verifier") ?? "";
      const record = authCodes.get(code);
      if (!record) {
        return json({ error: "invalid_grant", error_description: "unknown code" }, 400);
      }
      // Verify PKCE S256 — a wrong verifier must fail (this is what the mismatch test relies on).
      if (pkceS256(verifier) !== record.codeChallenge) {
        return json({ error: "invalid_grant", error_description: "PKCE verifier mismatch" }, 400);
      }
      authCodes.delete(code); // single-use
      const idToken = opts.omitIdToken ? undefined : await mintIdToken(record.nonce, opts.webId);
      const accessToken = await mintAccessToken();
      return tokenResponse(accessToken, idToken, tokenDpop);
    }

    if (grantType === "refresh_token") {
      const refresh = params.get("refresh_token");
      if (!refresh?.startsWith("refresh-")) {
        return json({ error: "invalid_grant", error_description: "unknown refresh token" }, 400);
      }
      // A refreshed ID token carries the same webid; nonce is not required on refresh.
      const idToken = opts.omitIdToken ? undefined : await mintIdTokenNoNonce(opts.webId);
      const accessToken = await mintAccessToken();
      return tokenResponse(accessToken, idToken, tokenDpop, "refresh-rotated");
    }

    return json({ error: "unsupported_grant_type" }, 400);
  }

  async function mintIdTokenNoNonce(webId: string | undefined): Promise<string> {
    const payload: Record<string, unknown> = { sub: "the-subject" };
    if (webId !== undefined) {
      payload.webid = webId;
    }
    return new SignJWT(b64urlJson(payload))
      .setProtectedHeader({ alg: "ES256", kid: "op-key-1", typ: "JWT" })
      .setIssuer(issuer)
      .setAudience(opts.clientId)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(privateKey);
  }

  function tokenResponse(
    accessToken: string,
    idToken: string | undefined,
    tokenDpop: string | undefined,
    refreshSuffix = "initial",
  ): Response {
    // Whether the OP saw a DPoP proof on the token request is asserted via captured headers, not
    // an echoed body field. `tokenDpop` is read so an unused-param lint does not fire.
    void tokenDpop;
    const out: Record<string, unknown> = {
      access_token: accessToken,
      token_type: "DPoP",
      expires_in: 600,
      scope: "openid webid offline_access",
    };
    if (idToken !== undefined) {
      out.id_token = idToken;
    }
    if (grantRefreshToken) {
      out.refresh_token = `refresh-${refreshSuffix}-${accessTokenCounter}`;
    }
    return json(out);
  }

  async function resourceEndpoint(
    url: string,
    method: string,
    headers: Record<string, string>,
  ): Promise<Response> {
    const dpop = headers.dpop;
    if (dpop) {
      const [h, p] = dpop.split(".");
      lastResourceProof = {
        header: decodeJwtPart(h as string),
        payload: decodeJwtPart(p as string),
      };
    }
    if (nextResourceNonce !== undefined) {
      const nonce = nextResourceNonce;
      nextResourceNonce = undefined; // single challenge
      return new Response("", {
        status: 401,
        headers: { "dpop-nonce": nonce, "www-authenticate": "DPoP" },
      });
    }
    return json({ ok: true, sawDpop: typeof dpop === "string", method, url });
  }

  return {
    fetch: (input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      const reqInit =
        input instanceof Request
          ? { method: input.method, headers: input.headers, ...(init ?? {}) }
          : init;
      return handle(url, reqInit);
    },
    authorize(authUrl: string) {
      const u = new URL(authUrl);
      const codeChallenge = u.searchParams.get("code_challenge") ?? "";
      const nonce = u.searchParams.get("nonce") ?? "";
      const state = u.searchParams.get("state") ?? "";
      const redirectUri = u.searchParams.get("redirect_uri") ?? "";
      const code = `code-${Math.random().toString(36).slice(2)}`;
      authCodes.set(code, { codeChallenge, nonce, state, redirectUri });
      return { code, state };
    },
    captured,
    opPublicJwk,
    rotateAccessToken() {
      // already rotates per mint (counter); this is a no-op marker kept for test readability
    },
    challengeNextResourceWithNonce(nonce: string) {
      nextResourceNonce = nonce;
    },
    lastResourceDpop() {
      return lastResourceProof;
    },
  };
}

/**
 * Read a request body into a string regardless of the `BodyInit` shape openid-client / our authed
 * fetch produced (it sends form bodies as `URLSearchParams`, and resource bodies as strings).
 */
async function readBody(body: unknown): Promise<string | undefined> {
  if (body === undefined || body === null) {
    return undefined;
  }
  if (typeof body === "string") {
    return body;
  }
  if (body instanceof URLSearchParams) {
    return body.toString();
  }
  // Fallback: let a real Request normalise anything else (Uint8Array, etc.).
  try {
    return await new Request("https://body.invalid/", {
      method: "POST",
      body: body as BodyInit,
    }).text();
  } catch {
    return undefined;
  }
}

function normalizeHeaders(h: HeadersInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) {
    return out;
  }
  if (h instanceof Headers) {
    h.forEach((v, k) => {
      out[k.toLowerCase()] = v;
    });
  } else if (Array.isArray(h)) {
    for (const [k, v] of h) {
      out[k.toLowerCase()] = v;
    }
  } else {
    for (const [k, v] of Object.entries(h)) {
      out[k.toLowerCase()] = v as string;
    }
  }
  return out;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Verify an ID token against the OP key — used by tests to cross-check signatures. */
export async function verifyWithOpKey(
  jws: string,
  opPublicJwk: JWK,
): Promise<Record<string, unknown>> {
  const { importJWK } = await import("jose");
  const key = await importJWK(opPublicJwk, "ES256");
  const { payload } = await jwtVerify(jws, key);
  return payload as Record<string, unknown>;
}

/** Compute the RFC 9449 `ath` for a token, the way a resource server would, for cross-checks. */
export function expectedAth(accessToken: string): string {
  return createHash("sha256").update(accessToken, "ascii").digest("base64url");
}

/** Compute the RFC 7638 thumbprint of a public JWK (for `jkt` cross-checks). */
export async function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk);
}
