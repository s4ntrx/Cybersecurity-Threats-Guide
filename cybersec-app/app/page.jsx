import Link from "next/link";
import { ArrowRight, Library, Search } from "lucide-react";
import CategoryIcon from "@/components/CategoryIcon";
import TopicCard from "@/components/TopicCard";
import { categories, formatDate, recentlyReviewed, stats } from "@/lib/content";

export default function HomePage() {
  const totals = stats();
  const counters = [
    ["Categories", totals.categories],
    ["Topics", totals.topics],
    ["Scripts", totals.scripts],
    ["Lines of code", totals.lines.toLocaleString("en")],
  ];

  return (
    <>
      <section className="border-b border-line">
        <div className="mx-auto max-w-6xl px-4 py-16 sm:py-24">
          <p className="text-sm font-bold uppercase tracking-[0.2em] text-cyan">Open-source security reference</p>
          <h1 className="mt-4 max-w-3xl text-4xl font-bold leading-tight text-white sm:text-5xl">
            Understand cyber threats. Detect them. Stop them.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-relaxed text-muted">
            Every topic pairs a plain-language explanation with standards mappings and Python scripts you can read and run in a lab.
            This site is generated from the repository, so it always matches the code.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href="#categories" className="inline-flex items-center gap-2 rounded-md bg-cyan px-5 py-3 text-sm font-bold text-bg transition-colors hover:bg-white">
              Browse the topics <ArrowRight className="size-4" aria-hidden="true" />
            </Link>
            <Link href="/search/" className="inline-flex items-center gap-2 rounded-md border border-line px-5 py-3 text-sm font-bold text-white transition-colors hover:border-cyan/60 hover:text-cyan">
              <Search className="size-4" aria-hidden="true" /> Search the guide
            </Link>
          </div>
          <dl className="mt-14 grid grid-cols-2 gap-4 sm:grid-cols-4">
            {counters.map(([label, value]) => (
              <div key={label} className="rounded-md border border-line bg-surface p-4">
                <dd className="text-3xl font-bold text-white">{value}</dd>
                <dt className="mt-1 text-xs uppercase tracking-wider text-muted">{label}</dt>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section id="categories" aria-labelledby="categories-heading" className="mx-auto max-w-6xl px-4 py-16">
        <h2 id="categories-heading" className="text-2xl font-bold text-white">Categories</h2>
        <ul className="mt-8 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {categories.map((category) => (
            <li key={category.slug}>
              <Link href={`/c/${category.slug}/`} className="group flex h-full flex-col gap-3 rounded-md border border-line bg-surface p-6 transition-colors hover:border-cyan/60">
                <div className="flex items-center justify-between text-cyan">
                  <CategoryIcon slug={category.slug} className="size-7" />
                  <span className="text-sm font-bold text-muted">{category.number}</span>
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-cyan">{category.title}</h3>
                <p className="line-clamp-3 text-sm leading-relaxed text-muted">{category.summary}</p>
                <p className="mt-auto pt-2 text-xs text-muted">
                  {category.topics.length} topics, {category.scriptCount} scripts
                </p>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="recent-heading" className="mx-auto max-w-6xl px-4 pb-8">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 id="recent-heading" className="text-2xl font-bold text-white">Recently reviewed</h2>
          <p className="text-sm text-muted">{totals.reviewed} of {totals.topics} topics carry a review date</p>
        </div>
        <ul className="mt-8 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {recentlyReviewed(6).map((topic) => (
            <li key={`${topic.category}/${topic.slug}`}><TopicCard topic={topic} /></li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="standards-heading" className="mx-auto max-w-6xl px-4 py-16">
        <div className="flex flex-col gap-4 rounded-md border border-line bg-surface p-8 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-2">
            <h2 id="standards-heading" className="flex items-center gap-2 text-xl font-bold text-white">
              <Library className="size-5 text-cyan" aria-hidden="true" /> Browse by standard
            </h2>
            <p className="max-w-xl text-sm leading-relaxed text-muted">
              Look up a MITRE ATT&CK technique, CWE, CAPEC or OWASP category and see which topics and scripts cover it.
            </p>
          </div>
          <Link href="/standards/" className="inline-flex shrink-0 items-center gap-2 rounded-md border border-line px-5 py-3 text-sm font-bold text-white transition-colors hover:border-cyan/60 hover:text-cyan">
            Open the index <ArrowRight className="size-4" aria-hidden="true" />
          </Link>
        </div>
      </section>
    </>
  );
}
