/** Category color map for graph nodes (OSS supply-chain malware wiki). */
export const CATEGORY_COLORS: Record<string, string> = {
  "registries": "#56d364",
  "advisories": "#e3b341",
  "code-search": "#79c0ff",
  "threat-intel": "#f97583",
  "scanners": "#d2a8ff",
};

export function getCategoryColor(category: string): string {
  return CATEGORY_COLORS[category] ?? "#8b949e";
}
