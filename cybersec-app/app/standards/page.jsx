import Link from "next/link";
import { ExternalLink } from "lucide-react";
import { standardsIndex } from "@/lib/content";

export const metadata = {
  title: "Browse by standard",
  description: "Find which topics and scripts cover a given MITRE ATT&CK technique, CWE, CAPEC or OWASP Top 10 category.",
};

export default function StandardsPage() {
  const grouped = Object.entries(Object.groupBy(standardsIndex(), (item) => item.kind));

  return (
    <div className="mx-auto max-w-4xl px-4 py-12">
      <h1 className="text-3xl font-bold text-white">Browse by standard</h1>
      <p className="mb-10 mt-3 leading-relaxed text-muted">
        Built from the &quot;Standards mapping&quot; table on each topic page. Topics written before that table existed are not listed yet.
      </p>
      <div className="space-y-12">
        {grouped.map(([kind, items]) => (
          <section key={kind} aria-labelledby={`h-${kind.replace(/\W+/g, "-")}`}>
            <h2 id={`h-${kind.replace(/\W+/g, "-")}`} className="border-b border-line pb-2 text-xl font-bold text-white">{kind}</h2>
            <ul className="mt-4 divide-y divide-line">
              {items.map((item) => (
                <li key={item.id} className="flex flex-col gap-2 py-4 sm:flex-row sm:items-start sm:justify-between">
                  <a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex shrink-0 items-center gap-1.5 font-bold text-cyan underline underline-offset-2">
                    {item.id} <ExternalLink className="size-3.5" aria-hidden="true" />
                  </a>
                  <ul className="flex flex-wrap gap-2 sm:justify-end">
                    {item.topics.map((topic) => (
                      <li key={`${topic.category}/${topic.slug}`}>
                        <Link href={`/c/${topic.category}/${topic.slug}/`} className="rounded border border-line px-2.5 py-1 text-sm text-ink transition-colors hover:border-cyan/60 hover:text-cyan">{topic.title}</Link>
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}
