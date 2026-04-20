import type { Page } from "@playwright/test";

export async function installMockVerifier(page: Page): Promise<{
  challengeHits: number;
  linkVerifyHits: number;
}> {
  let challengeHits = 0;
  let linkVerifyHits = 0;

  await page.route("**/challenge", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    challengeHits++;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        id: "fixture-challenge-0001",
        bytes: "AAAA",
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      }),
    });
  });

  await page.route("**/link-verify", async (route, req) => {
    if (req.method() !== "POST") return route.fallback();
    linkVerifyHits++;
    const body = req.postDataJSON();
    const shapeOk =
      typeof body?.cert_chain_proof === "string" &&
      typeof body?.device_sig_proof === "string" &&
      body.cert_chain_proof.length > 0 &&
      body.device_sig_proof.length > 0 &&
      ["rs2048", "rs4096"].includes(body?.cert_chain_type);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        verified: shapeOk,
        nullifier: body?.nullifier ?? "mock",
        id_verified: shapeOk,
        persisted: shapeOk,
      }),
    });
  });

  return {
    get challengeHits() { return challengeHits; },
    get linkVerifyHits() { return linkVerifyHits; },
  };
}
