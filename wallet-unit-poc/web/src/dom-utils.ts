// HTML escape helpers for code paths that have to use `innerHTML` (e.g.
// dynamic list rendering). Prefer `textContent` when possible. These
// helpers exist because `format.ts` is for value-formatting and mixing
// the two would tempt callers into thinking `humanBytes(...)` etc. need
// escaping (they don't).

export function escapeText(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function escapeAttr(s: string): string {
  return escapeText(s).replace(/"/g, "&quot;");
}
