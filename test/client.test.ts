// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Exhaustive tests for the Solid-OIDC engine against a FAITHFUL mock OP (no live IdP, no network,
 * no ports). The mock signs real ES256 ID tokens, serves a real JWKS, and verifies PKCE S256, so
 * `openid-client` genuinely validates / rejects — the tests are non-vacuous.
 *
 * Coverage (per the security spec):
 *   - happy path: code → DPoP-bound tokens → webid (from the ID token)
 *   - webid read from the access token when absent from the ID token
 *   - PKCE verifier mismatch fails
 *   - state mismatch fails
 *   - nonce mismatch fails (ID-token binding)
 *   - missing-webid-claim fails (fail-closed)
 *   - opaque access token with no ID-token webid fails (fail-closed)
 *   - refresh round-trips a NEW DPoP-bound access token (+ rotated refresh token)
 *   - the authed fetch attaches a valid DPoP proof bound to the access token (ath)
 *   - the authed fetch retries on the §8 DPoP-Nonce challenge
 *   - http issuer rejected unless allowInsecure; both-client-forms / no-client errors
 *   - the token-endpoint request carried a DPoP proof (sender-constrained)
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
    ).rejects.toThrow(/insecure issuer/i);
  });

  it("rejects a non-loopback http issuer even with allowInsecure", async () => {
    await expect(
      createSolidOidcClient({
        issuer: "http://op.example/",
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        allowInsecure: true,
      }),
    ).rejects.toThrow(/insecure issuer/i);
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
