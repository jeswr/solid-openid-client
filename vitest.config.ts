import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Pure unit tests — no live IdP, no network, no ports. A Map-backed fake
    // fetch stands in for the issuer's discovery / authorization / token /
    // resource endpoints. Fast and parallel-safe.
    include: ["test/**/*.test.ts"],
    exclude: ["**/node_modules/**"],
    testTimeout: 20_000,
  },
});
