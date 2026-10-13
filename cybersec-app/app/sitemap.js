import { categories, generatedAt, siteUrl, topics } from "@/lib/content";

export default function sitemap() {
  const entry = (path, lastModified = generatedAt) => ({ url: `${siteUrl}${path}`, lastModified });
  return [
    entry("/"),
    entry("/search/"),
    entry("/standards/"),
    ...categories.map((c) => entry(`/c/${c.slug}/`)),
    ...topics.flatMap((t) => [
      entry(`/c/${t.category}/${t.slug}/`, t.lastReviewed ?? generatedAt),
      ...t.scripts.map((s) => entry(`/c/${t.category}/${t.slug}/code/${s.slug}/`)),
    ]),
  ];
}
