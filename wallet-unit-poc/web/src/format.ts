// Small display-formatting helpers shared across screens + progress rows.

export function humanBytes(
  n: number | undefined,
  emptyLabel = "",
): string {
  if (!n || !Number.isFinite(n) || n <= 0) return emptyLabel;
  const units = ["B", "KB", "MB", "GB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
}
