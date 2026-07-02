// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
/**
 * Characterization / golden-master of the PUBLIC API surface.
 *
 * This test pins the observable public contract of `@jeswr/solid-openid-client` so a
 * behaviour-preserving internal refactor (splitting the god-module into focused files) can be
 * trusted to have changed STRUCTURE, not the surface consumers import against. It intentionally
 * asserts:
 *   1. the exact set of runtime VALUE exports (type-only exports erase at runtime), and
 *   2. the exact shape of the `SolidOidcClient` handle returned by a login,
 * so any accidental addition/removal/rename of a public symbol is a red test, not a silent drift.
 *
 * The type-level surface is separately pinned by the committed `dist/*.d.ts` (a reviewable diff).
 */

import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";
import { createSolidOidcClient } from "../src/index.js";
import { createMockOp } from "./mockOp.js";

const ISSUER = "https://op.example/";
const CLIENT_ID = "https://app.example/client-id.jsonld";
const REDIRECT_URI = "https://app.example/callback";
const WEBID = "https://alice.example/profile/card#me";

describe("public API surface (characterization)", () => {
  it("exports exactly the expected runtime value symbols", () => {
    // Type-only exports (interfaces / type aliases) are erased, so only runtime values appear here.
    expect(Object.keys(api).sort()).toEqual(
      [
        "DEFAULT_MAX_REPLAY_BODY_BYTES",
        "DEFAULT_SCOPE",
        "createSolidOidcClient",
        "generateDpopKeyPair",
        "resourceDpopProof",
        "toCryptoKeyPair",
      ].sort(),
    );
  });

  it("pins the value of the two exported constants", () => {
    expect(api.DEFAULT_SCOPE).toBe("openid webid offline_access");
    expect(api.DEFAULT_MAX_REPLAY_BODY_BYTES).toBe(10 * 1024 * 1024);
  });

  it("the SolidOidcClient handle exposes exactly the documented members", async () => {
    const op = await createMockOp({ issuer: ISSUER, clientId: CLIENT_ID, webId: WEBID });
    const client = await createSolidOidcClient({
      issuer: ISSUER,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      fetch: op.fetch,
    });
    // The handle is an object literal, so its own enumerable keys are the public members.
    expect(Object.keys(client).sort()).toEqual(
      [
        "authorizationUrl",
        "currentTokens",
        "currentWebId",
        "dpopKeyPair",
        "fetch",
        "handleCallback",
        "issuer",
        "refresh",
      ].sort(),
    );
    expect(typeof client.authorizationUrl).toBe("function");
    expect(typeof client.handleCallback).toBe("function");
    expect(typeof client.refresh).toBe("function");
    expect(typeof client.fetch).toBe("function");
    expect(typeof client.currentTokens).toBe("function");
    expect(typeof client.currentWebId).toBe("function");
    expect(client.issuer).toBe(ISSUER);
    // Before any login the session accessors are empty.
    expect(client.currentTokens()).toBeUndefined();
    expect(client.currentWebId()).toBeUndefined();
    // The DPoP keypair is exposed for persistence and carries a stable thumbprint (the token jkt).
    expect(typeof client.dpopKeyPair.thumbprint).toBe("string");
    expect(client.dpopKeyPair.thumbprint.length).toBeGreaterThan(0);
  });
});
