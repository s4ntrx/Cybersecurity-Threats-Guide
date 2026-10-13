import knowledge from "@/content/knowledge.json";

export const { categories, topics, source } = knowledge;
export const repoUrl = source.repo;
export const generatedAt = knowledge.generatedAt;

export const siteUrl =
  process.env.NEXT_PUBLIC_SITE_URL ||
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "http://localhost:3000");

const categoryBySlug = new Map(categories.map((c) => [c.slug, c]));
const topicByKey = new Map(topics.map((t) => [`${t.category}/${t.slug}`, t]));

export const getCategory = (slug) => categoryBySlug.get(slug);
export const getTopic = (category, slug) => topicByKey.get(`${category}/${slug}`);
export const topicsOf = (categorySlug) => (categoryBySlug.get(categorySlug)?.topics ?? []).map((slug) => topicByKey.get(`${categorySlug}/${slug}`));
export const getScript = (category, topic, scriptSlug) => getTopic(category, topic)?.scripts.find((s) => s.slug === scriptSlug);
export const githubFileUrl = (path) => `${repoUrl}/blob/${source.branch}/${path}`;
export const githubTreeUrl = (path) => `${repoUrl}/tree/${source.branch}/${path}`;

export function stats() {
  const scripts = topics.reduce((n, t) => n + t.scripts.length, 0);
  const lines = topics.reduce((n, t) => n + t.scripts.reduce((m, s) => m + s.lines, 0), 0);
  return {
    categories: categories.length,
    topics: topics.length,
    scripts,
    lines,
    reviewed: topics.filter((t) => t.lastReviewed).length,
  };
}

export const recentlyReviewed = (limit = 6) =>
  topics.filter((t) => t.lastReviewed).sort((a, b) => b.lastReviewed.localeCompare(a.lastReviewed) || a.title.localeCompare(b.title)).slice(0, limit);

const PATTERNS = [
  { kind: "OWASP Top 10", regex: /\bA\d{2}:20\d{2}\b/g, url: () => "https://owasp.org/Top10/2025/" },
  { kind: "MITRE ATT&CK", regex: /\bT\d{4}(?:\.\d{3})?\b/g, url: (id) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/` },
  { kind: "CWE", regex: /\bCWE-\d+\b/g, url: (id) => `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html` },
  { kind: "CAPEC", regex: /\bCAPEC-\d+\b/g, url: (id) => `https://capec.mitre.org/data/definitions/${id.slice(6)}.html` },
];

/** Every standards identifier mentioned in a topic's mapping table. */
export function identifiersOf(topic) {
  const found = [];
  for (const row of topic.mapping) {
    for (const { kind, regex, url } of PATTERNS) {
      for (const id of row.value.match(regex) ?? []) found.push({ kind, id, url: url(id) });
    }
  }
  return found.filter((item, i) => found.findIndex((o) => o.id === item.id) === i);
}

export function standardsIndex() {
  const index = new Map();
  for (const topic of topics) {
    for (const item of identifiersOf(topic)) {
      const key = `${item.kind}|${item.id}`;
      if (!index.has(key)) index.set(key, { ...item, topics: [] });
      index.get(key).topics.push({ category: topic.category, slug: topic.slug, title: topic.title });
    }
  }
  const order = PATTERNS.map((p) => p.kind);
  return [...index.values()].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.id.localeCompare(b.id, "en", { numeric: true }));
}

export const formatDate = (iso) =>
  iso ? new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(iso)) : null;
