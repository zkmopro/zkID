// Shared vitest scaffolding for the fetch-mocking pattern every client test
// uses: stub VITE_* env vars for the duration of the describe, and restore
// globalThis.fetch + unstub everything after each test. Call once inside a
// `describe` block.

import { afterEach, beforeEach, vi } from "vitest";

export function setupFetchMock(env: Record<string, string>): void {
  const originalFetch = globalThis.fetch;
  beforeEach(() => {
    for (const [key, value] of Object.entries(env)) {
      vi.stubEnv(key, value);
    }
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });
}
