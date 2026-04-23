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

export function formatDuration(ms: number): string {
  if (ms < 1_000) return `${ms.toFixed(0)} ms`;
  return `${(ms / 1_000).toFixed(1)} s`;
}

export function truncateMiddle(
  value: string | undefined | null,
  head: number,
  tail: number,
): string {
  if (value == null) return "—";
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}
