import { notFound } from "next/navigation";
import Link from "next/link";
import { ArrowRight, ExternalLink, FileCode2, TriangleAlert } from "lucide-react";
import StatusBadge from "@/components/StatusBadge";
import { formatDate, getCategory, getTopic, githubFileUrl, githubTreeUrl, identifiersOf, topics, topicsOf } from "@/lib/content";

export const dynamicParams = false;
export const generateStaticParams = () => topics.map((topic) => ({ category: topic.category, topic: topic.slug }));

export async function generateMetadata({ params }) {
  const { category, topic: slug } = await params;
  const topic = getTopic(category, slug);
  return topic ? { title: topic.title, description: topic.summary, alternates: { canonical: `/c/${category}/${slug}/` } } : {};
}

const kindLabel = { detection: "Detection", prevention: "Prevention", other: "Other" };

function ScriptList({ topic }) {
  return (
    <ul className="space-y-3">
      {topic.scripts.map((script) => (
        <li key={script.path}>
          <Link href={`/c/${topic.category}/${topic.slug}/code/${script.slug}/`} className="group block rounded-md border border-line bg-surface p-3 transition-colors hover:border-cyan/60">
            <span className="flex items-center gap-2 text-sm font-bold text-white group-hover:text-cyan">
              <FileCode2 className="size-4 shrink-0 text-cyan" aria-hidden="true" />
              <span className="break-all">{script.file}</span>
            </span>
            <span className="mt-1.5 flex flex-wrap gap-x-3 text-xs text-muted">
              <span>{kindLabel[script.kind]}</span>
              <span>{script.lines} lines</span>
              {script.needsPrivileges && <span className="text-amber">may need admin rights</span>}
            </span>
            {script.summary && <span className="mt-2 line-clamp-2 block text-xs leading-relaxed text-muted">{script.summary}</span>}
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default async function TopicPage({ params }) {
  const { category: categorySlug, topic: topicSlug } = await params;
  const category = getCategory(categorySlug);
  const topic = getTopic(categorySlug, topicSlug);
  if (!category || !topic) notFound();

  const siblings = topicsOf(categorySlug);
  const position = siblings.findIndex((t) => t.slug === topic.slug);
  const next = siblings[position + 1];
  const previous = siblings[position - 1];
  const identifiers = identifiersOf(topic);
  const tocEntries = topic.headings.filter((h) => h.depth === 2);

  return (
    <div className="mx-auto max-w-6xl px-4 py-12">
      <nav aria-label="Breadcrumb" className="text-sm text-muted">
        <Link href="/" className="hover:text-cyan">Home</Link> <span aria-hidden="true">/</span>{" "}
        <Link href={`/c/${category.slug}/`} className="hover:text-cyan">{category.title}</Link> <span aria-hidden="true">/</span>{" "}
        <span className="text-ink">{topic.title}</span>
      </nav>

      <header className="mt-6 space-y-4">
        <h1 className="text-3xl font-bold text-white sm:text-4xl">{topic.title}</h1>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-muted">
          <StatusBadge status={topic.status} />
          <span>{topic.lastReviewed ? `Last reviewed ${formatDate(topic.lastReviewed)}` : "No review date recorded"}</span>
          <a
            href={topic.readme ? githubFileUrl(topic.readme) : githubTreeUrl(topic.dir)}
            className="inline-flex items-center gap-1.5 text-cyan underline underline-offset-2"
            target="_blank"
            rel="noopener noreferrer"
          >
            {topic.readme ? "Edit this page on GitHub" : "View folder on GitHub"} <ExternalLink className="size-3.5" aria-hidden="true" />
          </a>
        </div>
        {identifiers.length > 0 && (
          <ul className="flex flex-wrap gap-2" aria-label="Standards covered">
            {identifiers.map((item) => (
              <li key={item.id}>
                <a href={item.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 rounded border border-line px-2.5 py-1 text-xs text-ink transition-colors hover:border-cyan/60 hover:text-cyan" title={`${item.kind} reference`}>
                  <span className="text-muted">{item.kind}</span> {item.id}
                </a>
              </li>
            ))}
          </ul>
        )}
      </header>

      {topic.status.startsWith("Draft") && (
        <p className="mt-6 flex items-start gap-3 rounded-md border border-amber/40 bg-surface p-4 text-sm text-ink">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber" aria-hidden="true" />
          This page is a draft: its scripts were tested in a lab, but its references still need an independent review.
        </p>
      )}

      <div className="mt-10 grid gap-10 lg:grid-cols-[minmax(0,1fr)_19rem]">
        <article>
          {topic.virtual ? (
            <div className="space-y-5">
              <p className="rounded-md border border-line bg-surface p-4 text-sm text-muted">
                This folder has scripts but no documentation page yet. The scripts below are real and linked to the repository.
              </p>
              <ScriptList topic={topic} />
            </div>
          ) : (
            <div className="prose-guide" dangerouslySetInnerHTML={{ __html: topic.html }} />
          )}
        </article>

        <aside className="space-y-8 lg:sticky lg:top-32 lg:self-start" aria-label="Topic navigation">
          {tocEntries.length > 1 && (
            <nav aria-label="On this page">
              <h2 className="mb-3 text-xs font-bold uppercase tracking-wider text-muted">On this page</h2>
              <ul className="space-y-1.5 border-l border-line text-sm">
                {tocEntries.map((entry) => (
                  <li key={entry.id}><a href={`#${entry.id}`} className="-ml-px block border-l border-transparent pl-3 text-muted transition-colors hover:border-cyan hover:text-cyan">{entry.text}</a></li>
                ))}
              </ul>
            </nav>
          )}
          {!topic.virtual && topic.scripts.length > 0 && (
            <section aria-labelledby="scripts-heading">
              <h2 id="scripts-heading" className="mb-3 text-xs font-bold uppercase tracking-wider text-muted">Scripts ({topic.scripts.length})</h2>
              <ScriptList topic={topic} />
            </section>
          )}
        </aside>
      </div>

      <nav aria-label="More topics in this category" className="mt-16 grid gap-4 border-t border-line pt-8 sm:grid-cols-2">
        {previous ? (
          <Link href={`/c/${category.slug}/${previous.slug}/`} className="rounded-md border border-line p-4 transition-colors hover:border-cyan/60">
            <span className="text-xs text-muted">Previous</span>
            <span className="mt-1 block font-bold text-white">{previous.title}</span>
          </Link>
        ) : <span />}
        {next && (
          <Link href={`/c/${category.slug}/${next.slug}/`} className="rounded-md border border-line p-4 text-right transition-colors hover:border-cyan/60">
            <span className="inline-flex items-center gap-1 text-xs text-muted">Next <ArrowRight className="size-3" aria-hidden="true" /></span>
            <span className="mt-1 block font-bold text-white">{next.title}</span>
          </Link>
        )}
      </nav>
    </div>
  );
}
