// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Exhaustive tests for the Solid-OIDC engine against a FAITHFUL mock OP (no live IdP, no network,
 * no ports). The mock signs real ES256 ID tokens, serves a real JWKS, and verifies PKCE S256, so
 * `openid-client` genuinely validates / rejects — the tests are non-vacuous.
 *
 * Coverage (per the security spec):
 *   - happy path: code → DPoP-bound tokens → webid (from the VERIFIED ID token)
 *   - an access-token-only webid is NOT trusted (fail-closed) — only the verified ID token is
 *   - PKCE verifier mismatch fails
 *   - state mismatch fails
 *   - nonce mismatch fails (ID-token binding)
 *   - missing-webid-claim fails (fail-closed)
 *   - opaque access token with no ID-token webid fails (fail-closed)
 *   - a caller cannot override reserved auth params (PKCE/state/nonce/scope/...)
 *   - refresh round-trips a NEW DPoP-bound access token (+ rotated, or carried-forward, refresh token)
 *   - the authed fetch attaches a valid DPoP proof bound to the access token (ath); §8 nonce retry
 *   - the authed fetch refuses plaintext http (no token leak); stream-body replay cap
 *   - http issuer/resource rejected unless allowInsecure (incl. IPv6 loopback); client-form errors
 *   - the token-endpoint request carried a DPoP proof (sender-constrained) + correct redirect_uri
 */

import { describe, expect, it } from "vitest";
import { createSolidOidcClient } from "../src/index.js";
import { createMockOp, expectedAth, jwkThumbprint, verifyWithOpKey } from "./mockOp.js";

const ISSUER = "https://op.example/";
const CLIENT_ID = "https://app.example/client-id.jsonld";
const REDIRECT_URI = "https://app.example/callback";
const WEBID = "https://alice.example/profile/card#me";

/** Drive a full login against a mock OP, returning the client + session + op handle. */
async function login(
  opOverrides: Parameters<typeof createMockOp>[0] | undefined = undefined,
  clientOverrides: Partial<Parameters<typeof createSolidOidcClient>[0]> = {},
) {
  const op = await createMockOp({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    webId: WEBID,
    ...opOverrides,
  });
  const client = await createSolidOidcClient({
    issuer: ISSUER,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    fetch: op.fetch,
    ...clientOverrides,
  });
  const { url, state } = await client.authorizationUrl();
  const { code, state: returnedState } = op.authorize(url);
  const callbackUrl = `${REDIRECT_URI}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(returnedState)}`;
  const session = await client.handleCallback({ url: callbackUrl }, state);
  return { op, client, session, url, state, code };
}

describe("createSolidOidcClient — construction guards", () => {
  it("rejects an http issuer without allowInsecure", async () => {
    await expect(
      createSolidOidcClient({
        issuer: "http://op.example/",
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      }),
    ).rejects.toThrow(/insecure http/i);
  });

  it("rejects a non-loopback http issuer even with allowInsecure", async () => {
    await expect(
      createSolidOidcClient({
        issuer: "http://op.example/",
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        allowInsecure: true,
      }),
    ).rejects.toThrow(/insecure http/i);
  });

  // Regression (roborev Low, whole-tree): IPv6 loopback (URL.hostname → "[::1]") must be accepted
  // with allowInsecure. The mock OP isn't reachable, but the transport guard must not be what
  // rejects it — so the failure (if any) is the discovery fetch, not an "insecure" rejection.
  it.each([
    "http://127.0.0.1:3000/",
    "http://[::1]:3000/",
    "http://localhost:3000/",
  ])("accepts the loopback issuer %s with allowInsecure (transport guard passes)", async (issuer) => {
    // Build a mock OP whose discovery answers regardless of the host (it matches on path).
    const op = await createMockOp({ issuer, clientId: CLIENT_ID, webId: WEBID });
    // Should NOT throw an "insecure" transport error — it constructs fine over the fake fetch.
    const client = await createSolidOidcClient({
      issuer,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
      allowInsecure: true,
    });
    expect(client.issuer).toBe(issuer);
  });

  it("rejects supplying BOTH clientId and client", async () => {
    await expect(
      createSolidOidcClient({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        client: { clientId: CLIENT_ID },
        redirectUri: REDIRECT_URI,
      }),
    ).rejects.toThrow(/EITHER/i);
  });

  it("rejects supplying NO client identity", async () => {
    await expect(
      createSolidOidcClient({
        issuer: ISSUER,
        redirectUri: REDIRECT_URI,
      } as Parameters<typeof createSolidOidcClient>[0]),
    ).rejects.toThrow(/client identity is required/i);
  });

  // Regression (roborev Medium, whole-tree-5): a redirectUri with a query/fragment is rejected
  // (openid-client strips query when deriving the token-endpoint redirect_uri → OP mismatch).
  it.each([
    "https://app.example/callback?tenant=a",
    "https://app.example/callback#frag",
  ])("rejects a redirectUri with a query/fragment: %s", async (redirectUri) => {
    await expect(
      createSolidOidcClient({ issuer: ISSUER, clientId: CLIENT_ID, redirectUri }),
    ).rejects.toThrow(/query string or fragment/i);
  });

  // Regression (roborev Medium, whole-tree-7): a non-https redirectUri (non-loopback) is rejected
  // — an authorization code must not be delivered over plaintext.
  it("rejects an http non-loopback redirectUri", async () => {
    await expect(
      createSolidOidcClient({
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectUri: "http://app.example/callback",
      }),
    ).rejects.toThrow(/redirectUri.*insecure|insecure http/i);
  });

  it("allows an http LOOPBACK redirectUri with allowInsecure", async () => {
    const op = await createMockOp({
      issuer: "http://localhost:3000/",
      clientId: CLIENT_ID,
      webId: WEBID,
    });
    const client = await createSolidOidcClient({
      issuer: "http://localhost:3000/",
      clientId: CLIENT_ID,
      redirectUri: "http://127.0.0.1:8080/callback", // loopback http
      fetch: op.fetch,
      allowInsecure: true,
    });
    expect(client.issuer).toBe("http://localhost:3000/");
  });

  // Regression (roborev High, whole-tree-5): even with allowInsecure (loopback issuer), a
  // discovered token_endpoint on a NON-loopback http host must be rejected (token-leak guard).
  it("rejects a discovered http non-loopback token_endpoint even with allowInsecure", async () => {
    const op = await createMockOp({
      issuer: "http://localhost:3000/",
      clientId: CLIENT_ID,
      webId: WEBID,
      evilTokenEndpoint: "http://evil.example/token", // non-loopback http
    });
    await expect(
      createSolidOidcClient({
        issuer: "http://localhost:3000/",
        clientId: CLIENT_ID,
        redirectUri: "http://localhost:3000/callback",
        fetch: op.fetch,
        allowInsecure: true,
      }),
    ).rejects.toThrow(/token_endpoint.*insecure|insecure.*endpoint/i);
  });
});

describe("authorizationUrl — PKCE / state / nonce ALWAYS present", () => {
  it("includes S256 PKCE, response_type=code, state, nonce, and the requested scopes", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const u = new URL(url);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(u.searchParams.get("state")).toBe(state.state);
    expect(u.searchParams.get("nonce")).toBe(state.nonce);
    expect(u.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(u.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    const scope = u.searchParams.get("scope") ?? "";
    expect(scope.split(" ")).toEqual(expect.arrayContaining(["openid", "webid", "offline_access"]));
    // PKCE verifier is kept client-side, NEVER on the URL.
    expect(url).not.toContain(state.codeVerifier);
  });

  it("generates a fresh verifier/state/nonce on each call", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const a = await client.authorizationUrl();
    const b = await client.authorizationUrl();
    expect(a.state.codeVerifier).not.toBe(b.state.codeVerifier);
    expect(a.state.state).not.toBe(b.state.state);
    expect(a.state.nonce).not.toBe(b.state.nonce);
  });

  it("passes through a non-reserved extra param (e.g. prompt)", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url } = await client.authorizationUrl({ prompt: "consent" });
    expect(new URL(url).searchParams.get("prompt")).toBe("consent");
  });

  // Regression (roborev Medium, whole-tree): a caller MUST NOT override security params.
  it.each([
    "state",
    "nonce",
    "code_challenge",
    "scope",
    "response_type",
    "redirect_uri",
    "client_id",
  ])("REJECTS an extraParams attempt to override the reserved param %s", async (reserved) => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    await expect(client.authorizationUrl({ [reserved]: "attacker" })).rejects.toThrow(/reserved/i);
  });
});

describe("handleCallback — happy path", () => {
  it("exchanges the code for DPoP-bound tokens and reads the webid from the ID token", async () => {
    const { session } = await login();
    expect(session.webId).toBe(WEBID);
    expect(session.issuer).toBe(ISSUER);
    // openid-client (oauth4webapi) lowercases token_type per the case-insensitive RFC rule.
    expect(session.tokens.tokenType.toLowerCase()).toBe("dpop");
    expect(session.tokens.accessToken).toBeTruthy();
    expect(session.tokens.refreshToken).toMatch(/^refresh-/);
    expect(session.tokens.idToken).toBeTruthy();
  });

  it("the returned ID token is genuinely OP-signed and carries iss/aud/webid", async () => {
    const { op, session } = await login();
    // Verify the ID token against the OP's REAL public key — proving the engine accepted a
    // properly-signed token and our test is not vacuous.
    const claims = await verifyWithOpKey(session.tokens.idToken as string, op.opPublicJwk);
    expect(claims.iss).toBe(ISSUER);
    expect(claims.aud).toBe(CLIENT_ID);
    expect(claims.webid).toBe(WEBID);
  });

  it("sent a DPoP proof to the token endpoint (sender-constrained exchange)", async () => {
    const { op } = await login();
    const tokenReq = op.captured.find((r) => r.url.endsWith("/token") && r.method === "POST");
    expect(tokenReq).toBeDefined();
    expect(tokenReq?.headers.dpop).toBeTruthy();
    // the proof header is a dpop+jwt
    const dpop = tokenReq?.headers.dpop as string;
    const header = JSON.parse(Buffer.from(dpop.split(".")[0] as string, "base64url").toString());
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk).toBeDefined();
  });

  it("exposes currentTokens()/currentWebId() after login", async () => {
    const { client, session } = await login();
    expect(client.currentWebId()).toBe(session.webId);
    expect(client.currentTokens()?.accessToken).toBe(session.tokens.accessToken);
  });

  // Regression (roborev Medium, whole-tree-7): a confidential client honours
  // token_endpoint_auth_method (client_secret_basic → Basic header, not a body secret).
  it("honours client_secret_basic for a confidential client (auth in the Basic header)", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: "confidential-client",
      webId: WEBID,
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      redirectUri: REDIRECT_URI,
      client: {
        clientId: "confidential-client",
        clientSecret: "s3cret",
        clientMetadata: { token_endpoint_auth_method: "client_secret_basic" },
      },
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await client.handleCallback(
      { url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` },
      state,
    );
    const tokenReq = op.captured.find((r) => r.url.endsWith("/token") && r.method === "POST");
    // Basic auth → Authorization: Basic base64(client_id:secret); the secret is NOT in the body.
    expect(tokenReq?.headers.authorization).toMatch(/^Basic /i);
    const decoded = Buffer.from(
      (tokenReq?.headers.authorization as string).slice("Basic ".length),
      "base64",
    ).toString("utf8");
    expect(decoded).toContain("s3cret");
    expect(tokenReq?.body ?? "").not.toContain("s3cret");
  });

  // client_secret_post (default for a confidential client) puts the secret in the body, not a header.
  it("defaults a confidential client to client_secret_post (secret in the body)", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: "confidential-post", webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      redirectUri: REDIRECT_URI,
      client: { clientId: "confidential-post", clientSecret: "p0stsecret" },
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await client.handleCallback(
      { url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` },
      state,
    );
    const tokenReq = op.captured.find((r) => r.url.endsWith("/token") && r.method === "POST");
    expect(tokenReq?.headers.authorization).toBeUndefined();
    expect(tokenReq?.body ?? "").toContain("p0stsecret");
  });

  it("accepts the params form of the callback input", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    const session = await client.handleCallback({ params: { code, state: returnedState } }, state);
    expect(session.webId).toBe(WEBID);
  });
});

describe("handleCallback — security: rejections (fail-closed)", () => {
  it("FAILS on a PKCE verifier mismatch", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    // Tamper the verifier the client will send to the token endpoint.
    const tampered = { ...state, codeVerifier: `${state.codeVerifier}TAMPERED` };
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, tampered)).rejects.toThrow();
  });

  it("FAILS on a state mismatch (CSRF)", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code } = op.authorize(url);
    // Redirect carries a DIFFERENT state than the one the client expects.
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=attacker-supplied-state`;
    await expect(client.handleCallback({ url: callbackUrl }, state)).rejects.toThrow();
  });

  it("FAILS on a nonce mismatch (ID-token binding)", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    // The OP minted an ID token bound to the REAL nonce; tell handleCallback to expect a
    // different one → the ID-token nonce check must fail.
    const tampered = { ...state, nonce: "a-different-nonce" };
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, tampered)).rejects.toThrow();
  });

  it("FAILS fail-closed when no webid is present in either token", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: undefined, // no webid in the ID token
      // and none in the access token
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, state)).rejects.toThrow(/webid/i);
  });

  it("FAILS fail-closed with an opaque access token and no ID-token webid", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: undefined,
      opaqueAccessToken: true,
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, state)).rejects.toThrow(/webid/i);
  });

  it("FAILS fail-closed when the webid claim is not an http(s) IRI", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: "urn:not-a-web-id",
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, state)).rejects.toThrow(/webid/i);
  });

  // Regression (roborev High, whole-tree-6): a bearer token returned to a DPoP-bound flow is a
  // sender-constraint DOWNGRADE — it must be rejected, never stored as a successful session.
  it("FAILS fail-closed when the OP returns a non-DPoP (bearer) token_type", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: WEBID,
      tokenTypeOverride: "Bearer", // downgrade
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await expect(
      client.handleCallback({ url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` }, state),
    ).rejects.toThrow(/dpop|sender-constrained/i);
  });

  // Regression (roborev High, whole-tree): a `webid` in the (CLIENT-UNVERIFIED) access token must
  // NOT establish a session — the WebID is read only from the verified ID token. The mock here
  // puts the webid ONLY in the access token; login must FAIL fail-closed.
  it("FAILS fail-closed: the access-token webid is NOT trusted (only the verified ID token is)", async () => {
    const op = await createMockOp({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: undefined, // no webid in the ID token
      webIdInAccessToken: WEBID, // present ONLY in the access token — must be ignored
    });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    const callbackUrl = `${REDIRECT_URI}?code=${code}&state=${returnedState}`;
    await expect(client.handleCallback({ url: callbackUrl }, state)).rejects.toThrow(/webid/i);
  });
});

describe("refresh", () => {
  it("round-trips a NEW DPoP-bound access token and a rotated refresh token", async () => {
    const { client, session } = await login();
    const firstAccess = session.tokens.accessToken;
    const firstRefresh = session.tokens.refreshToken as string;

    const refreshed = await client.refresh();
    expect(refreshed.accessToken).not.toBe(firstAccess); // genuinely new token
    expect(refreshed.tokenType.toLowerCase()).toBe("dpop");
    expect(refreshed.refreshToken).toBeTruthy();
    expect(refreshed.refreshToken).not.toBe(firstRefresh); // rotated
    // client state updated
    expect(client.currentTokens()?.accessToken).toBe(refreshed.accessToken);
  });

  it("sent a DPoP proof to the token endpoint on refresh (sender-constrained)", async () => {
    const { op, client } = await login();
    op.captured.length = 0; // clear, then refresh
    await client.refresh();
    const refreshReq = op.captured.find(
      (r) => r.url.endsWith("/token") && (r.body ?? "").includes("grant_type=refresh_token"),
    );
    expect(refreshReq).toBeDefined();
    expect(refreshReq?.headers.dpop).toBeTruthy();
  });

  it("THROWS when no refresh token is available", async () => {
    const { client } = await login({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: WEBID,
      grantRefreshToken: false,
    });
    await expect(client.refresh()).rejects.toThrow(/refresh token/i);
  });

  it("refreshes with an explicitly supplied refresh token", async () => {
    const { client, session } = await login();
    const refreshed = await client.refresh(session.tokens.refreshToken);
    expect(refreshed.accessToken).toBeTruthy();
  });

  // Regression (roborev Medium, whole-tree): a non-rotating OP omits refresh_token on refresh;
  // the client must carry the prior refresh token forward so a SECOND refresh still works.
  it("carries the prior refresh token forward when the OP does not rotate it", async () => {
    const { client, session } = await login({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      webId: WEBID,
      rotateRefreshTokenOnRefresh: false, // refresh responses omit refresh_token
    });
    const original = session.tokens.refreshToken as string;
    expect(original).toBeTruthy();

    const first = await client.refresh();
    // The response omitted refresh_token; the client kept the original one.
    expect(first.refreshToken).toBe(original);
    expect(client.currentTokens()?.refreshToken).toBe(original);

    // A SECOND refresh must still succeed (the token was not lost).
    const second = await client.refresh();
    expect(second.accessToken).toBeTruthy();
    expect(second.accessToken).not.toBe(first.accessToken);
    expect(second.refreshToken).toBe(original);
  });
});

describe("the authed fetch — DPoP proof bound to the access token (ath)", () => {
  it("attaches a DPoP proof whose ath is SHA-256(access_token) and jkt matches the keypair", async () => {
    const { op, client, session } = await login();
    const res = await client.fetch("https://op.example/resource/doc.ttl");
    expect(res.status).toBe(200);

    const proof = op.lastResourceDpop();
    expect(proof).toBeDefined();
    // header: dpop+jwt with the embedded public jwk
    expect(proof?.header.typ).toBe("dpop+jwt");
    expect(proof?.header.alg).toBe("ES256");
    expect(proof?.header.jwk).toBeDefined();
    // payload: htm/htu + ath bound to THIS access token
    expect(proof?.payload.htm).toBe("GET");
    expect(proof?.payload.htu).toBe("https://op.example/resource/doc.ttl");
    expect(proof?.payload.ath).toBe(expectedAth(session.tokens.accessToken));
    expect(proof?.payload.jti).toBeTruthy();

    // the proof's embedded jwk thumbprint equals the keypair the tokens are bound to (jkt)
    const embeddedJwk = proof?.header.jwk as Record<string, unknown>;
    const thumbprint = await jwkThumbprint(embeddedJwk);
    expect(thumbprint).toBe(client.dpopKeyPair.thumbprint);

    // the Authorization header carried the DPoP-scheme access token
    const resourceReq = op.captured.find((r) => r.url.includes("/resource/"));
    expect(resourceReq?.headers.authorization).toBe(`DPoP ${session.tokens.accessToken}`);
  });

  it("strips query/fragment from htu", async () => {
    const { op, client } = await login();
    await client.fetch("https://op.example/resource/doc.ttl?foo=bar#frag");
    const proof = op.lastResourceDpop();
    expect(proof?.payload.htu).toBe("https://op.example/resource/doc.ttl");
  });

  it("uses the request method in htm", async () => {
    const { op, client } = await login();
    await client.fetch("https://op.example/resource/doc.ttl", { method: "PUT", body: "x" });
    const proof = op.lastResourceDpop();
    expect(proof?.payload.htm).toBe("PUT");
  });

  it("mints a FRESH jti per request (proofs are single-use)", async () => {
    const { op, client } = await login();
    await client.fetch("https://op.example/resource/a.ttl");
    const first = op.lastResourceDpop()?.payload.jti;
    await client.fetch("https://op.example/resource/b.ttl");
    const second = op.lastResourceDpop()?.payload.jti;
    expect(first).toBeTruthy();
    expect(second).toBeTruthy();
    expect(first).not.toBe(second);
  });

  it("retries once on a §8 DPoP-Nonce challenge, echoing the nonce", async () => {
    const { op, client } = await login();
    op.challengeNextResourceWithNonce("server-nonce-xyz");
    const res = await client.fetch("https://op.example/resource/doc.ttl");
    // second attempt succeeded
    expect(res.status).toBe(200);
    // the retried proof carried the server nonce
    const proof = op.lastResourceDpop();
    expect(proof?.payload.nonce).toBe("server-nonce-xyz");
  });

  // Regression (roborev Medium): a Request input with NO init must keep its method + body.
  it("preserves the method AND body of a Request input passed with no init", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    const req = new Request("https://op.example/resource/doc.ttl", {
      method: "PUT",
      body: "the-body-bytes",
      headers: { "content-type": "text/turtle" },
    });
    await client.fetch(req);
    // the DPoP proof htm reflects PUT
    expect(op.lastResourceDpop()?.payload.htm).toBe("PUT");
    // the request that actually reached the RS carried PUT + the body + the content-type
    const sent = op.captured.find((r) => r.url.includes("/resource/"));
    expect(sent?.method).toBe("PUT");
    expect(sent?.body).toBe("the-body-bytes");
    expect(sent?.headers["content-type"]).toBe("text/turtle");
    expect(sent?.headers.authorization).toMatch(/^DPoP /);
  });

  // Regression (roborev Medium): the nonce retry must REPLAY the body (not consume-then-drop it).
  it("replays the request body on the §8 nonce retry", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    op.challengeNextResourceWithNonce("nonce-1");
    const req = new Request("https://op.example/resource/doc.ttl", {
      method: "POST",
      body: "replayable-payload",
    });
    const res = await client.fetch(req);
    expect(res.status).toBe(200);
    // BOTH the original (401) and the retry carried the SAME body.
    const resourceReqs = op.captured.filter((r) => r.url.includes("/resource/"));
    expect(resourceReqs.length).toBe(2);
    expect(resourceReqs[0]?.body).toBe("replayable-payload");
    expect(resourceReqs[1]?.body).toBe("replayable-payload");
    // and the retry's proof carried the server nonce
    expect(op.lastResourceDpop()?.payload.nonce).toBe("nonce-1");
  });

  // Regression (roborev Medium round 2): an explicit init.body that is a ReadableStream must also
  // be buffered so the §8 nonce retry replays it (not just the Request-body path).
  it("replays an explicit ReadableStream init.body on the §8 nonce retry", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    op.challengeNextResourceWithNonce("nonce-stream");
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("stream-payload"));
        controller.close();
      },
    });
    const res = await client.fetch("https://op.example/resource/doc.ttl", {
      method: "POST",
      body: stream,
      // a duplex is required by the spec for a stream body; harmless for the fake fetch.
      // @ts-expect-error duplex is not yet in the DOM RequestInit lib types
      duplex: "half",
    });
    expect(res.status).toBe(200);
    const resourceReqs = op.captured.filter((r) => r.url.includes("/resource/"));
    expect(resourceReqs.length).toBe(2);
    expect(resourceReqs[0]?.body).toBe("stream-payload");
    expect(resourceReqs[1]?.body).toBe("stream-payload"); // replayed, not consumed
  });

  // Regression (roborev Low round 2): Request transport fields are carried over, not dropped.
  it("carries over a Request's transport fields (credentials/mode/cache/redirect)", async () => {
    const { client } = await login();
    let seenInit: RequestInit | undefined;
    // Wrap the op fetch to capture the init the client actually passes to the underlying fetch.
    const op2 = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const spyFetch = (input: string | URL | Request, init?: RequestInit) => {
      seenInit = init;
      return op2.fetch(input, init);
    };
    const client2 = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: spyFetch,
    });
    const { url, state } = await client2.authorizationUrl();
    const { code, state: returnedState } = op2.authorize(url);
    await client2.handleCallback(
      { url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` },
      state,
    );
    void client; // the first login is just to ensure the helper path is exercised
    const ac = new AbortController();
    const req = new Request("https://op.example/resource/doc.ttl", {
      method: "GET",
      credentials: "include",
      mode: "cors",
      cache: "no-store",
      redirect: "follow",
      integrity: "sha256-abc",
      keepalive: true,
      referrer: "https://app.example/page",
      referrerPolicy: "no-referrer",
      signal: ac.signal,
    });
    await client2.fetch(req);
    // ALL the carried-over transport fields reach the underlying fetch.
    expect(seenInit?.credentials).toBe("include");
    expect(seenInit?.mode).toBe("cors");
    expect(seenInit?.cache).toBe("no-store");
    expect(seenInit?.redirect).toBe("follow");
    expect(seenInit?.integrity).toBe("sha256-abc");
    expect(seenInit?.keepalive).toBe(true);
    expect(seenInit?.referrer).toBe("https://app.example/page");
    expect(seenInit?.referrerPolicy).toBe("no-referrer");
    // A Request wraps the caller's signal in a derived AbortSignal (not the same object), so we
    // assert the signal is carried over and tracks the original's abort state, not identity.
    expect(seenInit?.signal).toBeInstanceOf(AbortSignal);
    expect(seenInit?.signal?.aborted).toBe(false);
    ac.abort();
    expect(seenInit?.signal?.aborted).toBe(true);
  });

  // Regression (roborev Medium round 3 + 4): an abort during stream-body buffering rejects
  // promptly AND actually CANCELS the active read (not just rejects the promise while the stream
  // keeps draining). We use our own reader, so cancel() reaches the underlying source.
  it("aborts promptly AND cancels the stream read while buffering when the signal fires", async () => {
    const { client } = await login();
    const ac = new AbortController();
    let cancelled = false;
    // A stream that never closes — without abort-aware buffering, reading it would hang forever.
    // Its `cancel` records that the source was actually told to stop.
    const neverEnding = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("partial"));
        // never close, never enqueue more
      },
      cancel() {
        cancelled = true;
      },
    });
    const p = client.fetch("https://op.example/resource/doc.ttl", {
      method: "POST",
      body: neverEnding,
      signal: ac.signal,
      // @ts-expect-error duplex is not yet in the DOM RequestInit lib types
      duplex: "half",
    });
    ac.abort();
    await expect(p).rejects.toThrow();
    // The underlying stream source was cancelled — the read did not keep draining in the background.
    expect(cancelled).toBe(true);
  });

  // Already-aborted signal rejects immediately (does not even start the request).
  it("rejects immediately if the signal is already aborted before buffering", async () => {
    const { client } = await login();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("x"));
      },
    });
    const p = client.fetch("https://op.example/resource/doc.ttl", {
      method: "POST",
      body: stream,
      signal: AbortSignal.abort(),
      // @ts-expect-error duplex is not yet in the DOM RequestInit lib types
      duplex: "half",
    });
    await expect(p).rejects.toThrow();
  });

  // An explicit init.body overrides a Request body (fetch precedence).
  it("lets an explicit init override a Request's method/body", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    const req = new Request("https://op.example/resource/doc.ttl", {
      method: "POST",
      body: "request-body",
    });
    await client.fetch(req, { method: "PATCH", body: "init-body" });
    const sent = op.captured.find((r) => r.url.includes("/resource/"));
    expect(sent?.method).toBe("PATCH");
    expect(sent?.body).toBe("init-body");
    expect(op.lastResourceDpop()?.payload.htm).toBe("PATCH");
  });

  it("THROWS if called before any token is available", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    await expect(client.fetch("https://op.example/resource/doc.ttl")).rejects.toThrow(
      /no access token/i,
    );
  });

  it("binds the proof to the REFRESHED access token after a refresh", async () => {
    const { op, client } = await login();
    const refreshed = await client.refresh();
    await client.fetch("https://op.example/resource/doc.ttl");
    const proof = op.lastResourceDpop();
    expect(proof?.payload.ath).toBe(expectedAth(refreshed.accessToken));
  });

  // Regression (roborev High, whole-tree): never send the DPoP token over plaintext http.
  it("REFUSES to attach the DPoP token to an http resource URL (no allowInsecure)", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    await expect(client.fetch("http://op.example/resource/doc.ttl")).rejects.toThrow(
      /insecure http|plaintext/i,
    );
    // and it never even reached the network (no DPoP token leaked)
    expect(op.captured.filter((r) => r.url.includes("/resource/"))).toHaveLength(0);
  });

  it("allows an http LOOPBACK resource URL when allowInsecure is set", async () => {
    const op = await createMockOp({
      issuer: "http://localhost:3000/",
      clientId: CLIENT_ID,
      webId: WEBID,
    });
    const client = await createSolidOidcClient({
      issuer: "http://localhost:3000/",
      clientId: CLIENT_ID,
      redirectUri: "http://localhost:3000/callback",
      fetch: op.fetch,
      allowInsecure: true,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await client.handleCallback(
      { url: `http://localhost:3000/callback?code=${code}&state=${returnedState}` },
      state,
    );
    // an http loopback resource is permitted
    const res = await client.fetch("http://localhost:3000/resource/doc.ttl");
    expect(res.status).toBe(200);
  });

  // Regression (roborev Medium, whole-tree): a stream body over the replay cap is rejected, not
  // buffered (memory-safety). Cap set tiny here to exercise it deterministically.
  it("REJECTS a stream body larger than the replay-buffer cap", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
      maxReplayBodyBytes: 8, // tiny cap
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await client.handleCallback(
      { url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` },
      state,
    );
    const big = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("this body is well over eight bytes"));
        controller.close();
      },
    });
    await expect(
      client.fetch("https://op.example/resource/doc.ttl", {
        method: "PUT",
        body: big,
        // @ts-expect-error duplex is not yet in the DOM RequestInit lib types
        duplex: "half",
      }),
    ).rejects.toThrow(/cap|exceeds/i);
  });

  it("allows a stream body within the cap", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
      maxReplayBodyBytes: 1024,
    });
    const { url, state } = await client.authorizationUrl();
    const { code, state: returnedState } = op.authorize(url);
    await client.handleCallback(
      { url: `${REDIRECT_URI}?code=${code}&state=${returnedState}` },
      state,
    );
    op.captured.length = 0;
    const small = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("small"));
        controller.close();
      },
    });
    const res = await client.fetch("https://op.example/resource/doc.ttl", {
      method: "PUT",
      body: small,
      // @ts-expect-error duplex is not yet in the DOM RequestInit lib types
      duplex: "half",
    });
    expect(res.status).toBe(200);
    const sent = op.captured.find((r) => r.url.includes("/resource/"));
    expect(sent?.body).toBe("small");
  });

  // Regression (roborev Medium, whole-tree-4): a RELATIVE URL must resolve against a document base
  // (browser-like), not throw — matching DOM fetch. We stub globalThis.location for the test.
  it("resolves a relative resource URL against the document base (browser-like)", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    const hadLocation = "location" in globalThis;
    const prev = (globalThis as { location?: unknown }).location;
    (globalThis as { location?: unknown }).location = { href: "https://op.example/app/" };
    try {
      const res = await client.fetch("/resource/doc.ttl");
      expect(res.status).toBe(200);
      // resolved to the absolute https URL under the document origin
      const sent = op.captured.find((r) => r.url.includes("/resource/"));
      expect(sent?.url).toBe("https://op.example/resource/doc.ttl");
      expect(op.lastResourceDpop()?.payload.htu).toBe("https://op.example/resource/doc.ttl");
    } finally {
      if (hadLocation) {
        (globalThis as { location?: unknown }).location = prev;
      } else {
        // biome-ignore lint/performance/noDelete: test cleanup of a stubbed global
        delete (globalThis as { location?: unknown }).location;
      }
    }
  });

  // Regression (roborev Low, round 5): document.baseURI (which honours <base href>) is preferred
  // over location.href, matching native fetch.
  it("prefers document.baseURI (<base href>) over location.href for relative URLs", async () => {
    const { op, client } = await login();
    op.captured.length = 0;
    const g = globalThis as { document?: unknown; location?: unknown };
    const hadDoc = "document" in globalThis;
    const hadLoc = "location" in globalThis;
    const prevDoc = g.document;
    const prevLoc = g.location;
    // location says one origin/path, but <base href> (document.baseURI) says another — base wins.
    g.location = { href: "https://op.example/some/other/page" };
    g.document = { baseURI: "https://op.example/base/" };
    try {
      const res = await client.fetch("doc.ttl"); // relative, no leading slash → resolved vs base
      expect(res.status).toBe(200);
      const sent = op.captured.find((r) => r.url.includes("doc.ttl"));
      expect(sent?.url).toBe("https://op.example/base/doc.ttl");
    } finally {
      if (hadDoc) {
        g.document = prevDoc;
      } else {
        // biome-ignore lint/performance/noDelete: test cleanup of a stubbed global
        delete g.document;
      }
      if (hadLoc) {
        g.location = prevLoc;
      } else {
        // biome-ignore lint/performance/noDelete: test cleanup of a stubbed global
        delete g.location;
      }
    }
  });

  // Server-side (no document base): a relative URL throws a clear error rather than a raw URL parse.
  it("throws a clear error for a relative URL with no document base (server-side)", async () => {
    const { client } = await login();
    const g = globalThis as { document?: unknown; location?: unknown };
    const hadDoc = "document" in globalThis;
    const hadLoc = "location" in globalThis;
    const prevDoc = g.document;
    const prevLoc = g.location;
    // biome-ignore lint/performance/noDelete: ensure no document base for this assertion
    delete g.document;
    // biome-ignore lint/performance/noDelete: ensure no document base for this assertion
    delete g.location;
    try {
      await expect(client.fetch("/resource/doc.ttl")).rejects.toThrow(/absolute URL/i);
    } finally {
      if (hadDoc) {
        g.document = prevDoc;
      }
      if (hadLoc) {
        g.location = prevLoc;
      }
    }
  });
});

describe("scope handling", () => {
  it("forces openid into a custom scope and de-dups", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
      scope: "webid webid offline_access",
    });
    const { url } = await client.authorizationUrl();
    const scope = new URL(url).searchParams.get("scope") ?? "";
    const parts = scope.split(" ");
    expect(parts[0]).toBe("openid");
    expect(parts.filter((p) => p === "webid")).toHaveLength(1);
  });
});

describe("DPoP keypair reuse (persisted-session restart)", () => {
  it("reuses a supplied keypair so the jkt is stable across client instances", async () => {
    const { client: first, op } = await login();
    const keyPair = first.dpopKeyPair;

    // A second client created with the SAME keypair (e.g. a restored session) has the same jkt.
    const second = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
      dpopKeyPair: keyPair,
    });
    expect(second.dpopKeyPair.thumbprint).toBe(first.dpopKeyPair.thumbprint);
  });
});
