export const config = { runtime: "edge" };

const UPSTREAM = {
  keys: "https://github.com/zkmopro/zkID/releases/download/latest",
  "smt-snapshot":
    "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest",
};

export default async function handler(req) {
  const { searchParams } = new URL(req.url);
  const base = searchParams.get("base");
  const path = searchParams.get("path");

  const upstream = UPSTREAM[base];
  if (!upstream || !path) return new Response("Bad Request", { status: 400 });

  const target = `${upstream}/${path}`;
  const response = await fetch(target, { redirect: "follow" });
  if (!response.ok) {
    return new Response(`Upstream error: ${response.status}`, {
      status: response.status,
    });
  }

  const contentType =
    response.headers.get("Content-Type") ?? "application/octet-stream";
  return new Response(response.body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Cache-Control": "public, max-age=3600, immutable",
    },
  });
}
