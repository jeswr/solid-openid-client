// src/client.ts
import * as oidc from "openid-client";

// node_modules/@jeswr/solid-dpop/dist/esm/authCode.js
import { createHash as createHash2, randomBytes, randomUUID as randomUUID2 } from "node:crypto";

// node_modules/@jeswr/solid-dpop/dist/esm/dpop.js
import { createHash, randomUUID } from "node:crypto";
var josePromise;
function loadJose() {
  if (!josePromise) {
    josePromise = import("jose");
  }
  return josePromise;
}
var DPOP_ALG = "ES256";
function canonicalHtu(uri) {
  const u = new URL(uri);
  u.search = "";
  u.hash = "";
  return u.toString();
}
function accessTokenHash(accessToken) {
  return createHash("sha256").update(accessToken, "ascii").digest("base64url");
}
async function toDpopKeyPair(publicKey, privateKey) {
  const { exportJWK, calculateJwkThumbprint } = await loadJose();
  const publicJwk = await exportJWK(publicKey);
  const thumbprint = await calculateJwkThumbprint(publicJwk);
  return { publicKey, privateKey, publicJwk, thumbprint };
}
async function generateDpopKeyPair() {
  const { generateKeyPair } = await loadJose();
  const { publicKey, privateKey } = await generateKeyPair(DPOP_ALG, { extractable: true });
  return toDpopKeyPair(publicKey, privateKey);
}
async function createDpopProof(params) {
  const { keyPair, htm, htu, accessToken, nonce } = params;
  const payload = {
    htm: htm.toUpperCase(),
    htu: canonicalHtu(htu),
    jti: randomUUID()
  };
  if (accessToken !== void 0) {
    payload["ath"] = accessTokenHash(accessToken);
  }
  if (nonce !== void 0) {
    payload["nonce"] = nonce;
  }
  const { SignJWT } = await loadJose();
  return new SignJWT(payload).setProtectedHeader({
    typ: "dpop+jwt",
    alg: DPOP_ALG,
    jwk: keyPair.publicJwk
  }).setIssuedAt().sign(keyPair.privateKey);
}

// src/dpop.ts
function toCryptoKeyPair(keyPair) {
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}
function resourceDpopProof(keyPair, method, url, accessToken, nonce) {
  return createDpopProof(
    nonce === void 0 ? { keyPair, htm: method, htu: url, accessToken } : { keyPair, htm: method, htu: url, accessToken, nonce }
  );
}

// src/client.ts
var DEFAULT_SCOPE2 = "openid webid offline_access";
function normalizeScope(scope) {
  if (scope === void 0 || scope.trim() === "") {
    return DEFAULT_SCOPE2;
  }
  const parts = scope.split(/\s+/).filter((s) => s.length > 0);
  if (!parts.includes("openid")) {
    parts.unshift("openid");
  }
  return [...new Set(parts)].join(" ");
}
function resolveIdentity(opts) {
  if (opts.client !== void 0 && opts.clientId !== void 0) {
    throw new Error(
      "createSolidOidcClient: supply EITHER `clientId` (a Client ID Document URL) OR `client`, not both."
    );
  }
  if (opts.client !== void 0) {
    return opts.client;
  }
  if (opts.clientId !== void 0) {
    return { clientId: opts.clientId };
  }
  throw new Error(
    "createSolidOidcClient: a client identity is required \u2014 pass `clientId` (a Client ID Document URL, the primary path) or a full `client`."
  );
}
function hasSecret(id) {
  return "clientSecret" in id && typeof id.clientSecret === "string" && id.clientSecret.length > 0;
}
function assertIssuerTransport2(issuer, allowInsecure) {
  let u;
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
      `createSolidOidcClient: refusing an insecure issuer (${issuer}). Solid-OIDC requires https; http: is permitted only for a loopback dev OP with \`allowInsecure: true\`.`
    );
  }
  throw new Error(
    `createSolidOidcClient: unsupported issuer scheme in ${issuer} (expected https:).`
  );
}
function extractWebId(tokenResponse) {
  const idClaims = tokenResponse.claims();
  const fromId = idClaims?.webid;
  if (typeof fromId === "string" && isHttpUri(fromId)) {
    return fromId;
  }
  const fromAt = readAccessTokenWebId(tokenResponse.access_token);
  if (fromAt !== void 0 && isHttpUri(fromAt)) {
    return fromAt;
  }
  throw new Error(
    "Solid-OIDC login produced no resolvable `webid` claim in the ID token or access token; refusing to return a session without a WebID (fail-closed)."
  );
}
function isHttpUri(value) {
  try {
    const u = new URL(value);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}
function readAccessTokenWebId(accessToken) {
  const parts = accessToken.split(".");
  if (parts.length !== 3) {
    return void 0;
  }
  try {
    const payloadB64 = parts[1];
    const json = Buffer.from(payloadB64, "base64url").toString("utf8");
    const payload = JSON.parse(json);
    const webid = payload.webid;
    return typeof webid === "string" ? webid : void 0;
  } catch {
    return void 0;
  }
}
function toSolidTokens(res) {
  const base = {
    accessToken: res.access_token,
    tokenType: res.token_type
  };
  return {
    ...base,
    ...res.refresh_token !== void 0 ? { refreshToken: res.refresh_token } : {},
    ...res.id_token !== void 0 ? { idToken: res.id_token } : {},
    ...res.expires_in !== void 0 ? { expiresIn: res.expires_in } : {},
    ...res.scope !== void 0 ? { scope: res.scope } : {}
  };
}
async function createSolidOidcClient(opts) {
  const allowInsecure = opts.allowInsecure === true;
  assertIssuerTransport2(opts.issuer, allowInsecure);
  const identity = resolveIdentity(opts);
  const scope = normalizeScope(opts.scope);
  const redirectUri = opts.redirectUri;
  const userFetch = opts.fetch ?? globalThis.fetch;
  const dpopKeyPair = opts.dpopKeyPair ?? await generateDpopKeyPair();
  const baseMetadata = {
    client_id: identity.clientId,
    redirect_uris: [redirectUri],
    ..."clientMetadata" in identity && identity.clientMetadata || {}
  };
  const clientAuth = hasSecret(identity) ? oidc.ClientSecretPost(identity.clientSecret) : oidc.None();
  if (hasSecret(identity)) {
    baseMetadata.client_secret = identity.clientSecret;
  }
  const discoveryOptions = {
    [oidc.customFetch]: adaptCustomFetch(userFetch),
    ...allowInsecure ? { execute: [oidc.allowInsecureRequests] } : {}
  };
  const config = await oidc.discovery(
    new URL(opts.issuer),
    identity.clientId,
    baseMetadata,
    clientAuth,
    discoveryOptions
  );
  const discoveredIssuer = config.serverMetadata().issuer;
  if (discoveredIssuer !== opts.issuer && discoveredIssuer !== stripTrailingSlash(opts.issuer)) {
    if (stripTrailingSlash(discoveredIssuer) !== stripTrailingSlash(opts.issuer)) {
      throw new Error(
        `createSolidOidcClient: discovered issuer (${discoveredIssuer}) does not match the requested issuer (${opts.issuer}).`
      );
    }
  }
  const dpopHandle = oidc.getDPoPHandle(config, toCryptoKeyPair(dpopKeyPair));
  let currentTokens;
  let currentWebId;
  const authedFetch2 = async (input, init) => {
    if (currentTokens === void 0) {
      throw new Error(
        "authedFetch: no access token yet \u2014 call handleCallback()/refresh() before fetching."
      );
    }
    const accessToken = currentTokens.accessToken;
    const reqInput = input instanceof Request ? input : void 0;
    const url = reqInput ? reqInput.url : input.toString();
    const method = (init?.method ?? reqInput?.method ?? "GET").toUpperCase();
    const baseInit = {
      ...reqInput ? {
        method: reqInput.method,
        redirect: reqInput.redirect,
        ...reqInput.signal ? { signal: reqInput.signal } : {}
      } : {},
      ...init ?? {},
      method
    };
    let bufferedBody;
    if (init && "body" in init) {
      bufferedBody = init.body ?? void 0;
    } else if (reqInput && reqInput.body !== null) {
      bufferedBody = await reqInput.clone().arrayBuffer();
    }
    const buildHeaders = (proof) => {
      const headers = new Headers(reqInput?.headers ?? void 0);
      if (init?.headers) {
        new Headers(init.headers).forEach((v, k) => {
          headers.set(k, v);
        });
      }
      headers.set("authorization", `DPoP ${accessToken}`);
      headers.set("dpop", proof);
      return headers;
    };
    const doFetch = async (nonce) => {
      const proof = await resourceDpopProof(dpopKeyPair, method, url, accessToken, nonce);
      const req = {
        ...baseInit,
        headers: buildHeaders(proof),
        ...bufferedBody !== void 0 ? { body: bufferedBody } : {}
      };
      return userFetch(url, req);
    };
    const res = await doFetch();
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
    fetch: authedFetch2,
    currentTokens: () => currentTokens,
    currentWebId: () => currentWebId,
    async authorizationUrl(extraParams) {
      const codeVerifier = oidc.randomPKCECodeVerifier();
      const codeChallenge = await oidc.calculatePKCECodeChallenge(codeVerifier);
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const params = {
        redirect_uri: redirectUri,
        scope,
        response_type: "code",
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        nonce,
        ...extraParams ?? {}
      };
      const url = oidc.buildAuthorizationUrl(config, params);
      return {
        url: url.href,
        state: { codeVerifier, state, nonce, redirectUri }
      };
    },
    async handleCallback(callback, reqState) {
      const currentUrl = callbackToUrl(callback);
      const tokenResponse = await oidc.authorizationCodeGrant(
        config,
        currentUrl,
        {
          pkceCodeVerifier: reqState.codeVerifier,
          expectedState: reqState.state,
          // exact-match CSRF check (openid-client throws on mismatch)
          expectedNonce: reqState.nonce,
          // exact-match ID-token nonce check
          idTokenExpected: true
          // a Solid-OIDC login MUST return an ID token
        },
        void 0,
        { DPoP: dpopHandle }
      );
      const webId = extractWebId(tokenResponse);
      const tokens = toSolidTokens(tokenResponse);
      currentTokens = tokens;
      currentWebId = webId;
      return { webId, issuer: opts.issuer, tokens };
    },
    async refresh(refreshTokenArg) {
      const refreshToken = refreshTokenArg ?? currentTokens?.refreshToken;
      if (refreshToken === void 0) {
        throw new Error(
          "refresh: no refresh token available \u2014 supply one or log in with `offline_access` first."
        );
      }
      const res = await oidc.refreshTokenGrant(config, refreshToken, void 0, {
        DPoP: dpopHandle
      });
      const tokens = toSolidTokens(res);
      currentTokens = tokens;
      const refreshedWebId = res.claims()?.webid;
      if (typeof refreshedWebId === "string" && isHttpUri(refreshedWebId)) {
        currentWebId = refreshedWebId;
      }
      return tokens;
    }
  };
}
function callbackToUrl(callback) {
  if ("url" in callback) {
    return callback.url instanceof URL ? callback.url : new URL(callback.url);
  }
  const u = new URL("https://callback.invalid/");
  const params = callback.params instanceof URLSearchParams ? callback.params : new URLSearchParams(callback.params);
  for (const [k, v] of params) {
    u.searchParams.set(k, v);
  }
  return u;
}
function stripTrailingSlash(s) {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}
function adaptCustomFetch(userFetch) {
  return (url, options) => {
    const init = {
      method: options.method,
      headers: options.headers,
      redirect: options.redirect,
      ...options.body !== void 0 ? { body: options.body } : {},
      ...options.signal !== void 0 ? { signal: options.signal } : {}
    };
    return userFetch(url, init);
  };
}
export {
  DEFAULT_SCOPE2 as DEFAULT_SCOPE,
  createSolidOidcClient,
  generateDpopKeyPair,
  resourceDpopProof,
  toCryptoKeyPair
};
//# sourceMappingURL=index.js.map
