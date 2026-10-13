import { notFound } from "next/navigation";
import Link from "next/link";
import CategoryIcon from "@/components/CategoryIcon";
import TopicCard from "@/components/TopicCard";
import { categories, getCategory, githubTreeUrl, topicsOf } from "@/lib/content";

export const dynamicParams = false;
export const generateStaticParams = () => categories.map((category) => ({ category: category.slug }));

export async function generateMetadata({ params }) {
  const category = getCategory((await params).category);
  return category ? { title: category.title, description: category.summary, alternates: { canonical: `/c/${category.slug}/` } } : {};
}

export default async function CategoryPage({ params }) {
  const category = getCategory((await params).category);
  if (!category) notFound();
  const topics = topicsOf(category.slug);

  return (
    <div className="mx-auto max-w-6xl px-4 py-12">
      <nav aria-label="Breadcrumb" className="text-sm text-muted">
        <Link href="/" className="hover:text-cyan">Home</Link> <span aria-hidden="true">/</span> <span className="text-ink">{category.title}</span>
      </nav>

      <header className="mt-6 flex items-start gap-5">
        <span className="flex size-14 shrink-0 items-center justify-center rounded-md border border-line bg-surface text-cyan">
          <CategoryIcon slug={category.slug} className="size-7" />
        </span>
        <div>
          <p className="text-sm font-bold text-cyan">{category.number}</p>
          <h1 className="text-3xl font-bold text-white sm:text-4xl">{category.title}</h1>
          <p className="mt-3 max-w-3xl leading-relaxed text-muted">{category.summary}</p>
        </div>
      </header>

      <section aria-labelledby="topics-heading" className="mt-12">
        <h2 id="topics-heading" className="text-xl font-bold text-white">{topics.length} topics, {category.scriptCount} scripts</h2>
        <ul className="mt-6 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {topics.map((topic) => (
            <li key={topic.slug}><TopicCard topic={topic} /></li>
          ))}
        </ul>
      </section>

      {category.html && (
        <details className="mt-14 rounded-md border border-line bg-surface">
          <summary className="cursor-pointer select-none px-5 py-4 font-bold text-white">Read the full category guide</summary>
          <div className="prose-guide border-t border-line px-5 pb-6 pt-4" dangerouslySetInnerHTML={{ __html: category.html }} />
        </details>
      )}

      <p className="mt-8 text-sm text-muted">
        Source folder:{" "}
        <a href={githubTreeUrl(category.dirName)} className="text-cyan underline underline-offset-2" target="_blank" rel="noopener noreferrer">{category.dirName}</a>
      </p>
    </div>
  );
}
