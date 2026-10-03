/**
 * Whether `el` is shown in dark mode: when its `color-scheme` allows only dark, or allows both and the
 * user prefers dark (the dialog's default is `light dark`).
 */
export function isDark(el: Element): boolean {
  const schemes = getComputedStyle(el).colorScheme?.split(/\s+/) ?? [];
  if (!schemes.includes('dark')) return false;
  return !schemes.includes('light') || matchMedia('(prefers-color-scheme: dark)').matches;
}
