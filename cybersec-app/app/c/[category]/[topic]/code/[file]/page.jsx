import { notFound } from "next/navigation";
import Link from "next/link";
import { ExternalLink, ShieldAlert, Terminal } from "lucide-react";
import CopyButton from "@/components/CopyButton";
import { getCategory, getScript, getTopic, githubFileUrl, topics } from "@/lib/content";
import { highlightedLines } from "@/lib/code";

export const dynamicParams = false;
export const generateStaticParams = () =>
  topics.flatMap((topic) => topic.scripts.map((script) => ({ category: topic.category, topic: topic.slug, file: script.slug })));

export async function generateMetadata({ params }) {
  const { category, topic, file } = await params;
  const script = getScript(category, topic, file);
  if (!script) return {};
  return {
    title: `${script.file} (${getTopic(category, topic).title})`,
    description: script.summary || `Source code of ${script.file}`,
    alternates: { canonical: `/c/${category}/${topic}/code/${file}/` },
  };
}

export default async function ScriptPage({ params }) {
  const { category: categorySlug, topic: topicSlug, file } = await params;
  const category = getCategory(categorySlug);
  const topic = getTopic(categorySlug, topicSlug);
  const script = getScript(categorySlug, topicSlug, file);
  if (!category || !topic || !script) notFound();

  const lines = highlightedLines(script.source, script.language);
  const runnable = script.extension === ".py" || script.extension === ".sh";
  const interpreter = script.extension === ".py" ? "python3" : "bash";
  const command = `cd ${script.directory}\n${interpreter} ${script.file} --help`;

  return (
    <div className="mx-auto max-w-6xl px-4 py-12">
      <nav aria-label="Breadcrumb" className="text-sm text-muted">
        <Link href="/" className="hover:text-cyan">Home</Link> <span aria-hidden="true">/</span>{" "}
        <Link href={`/c/${category.slug}/`} className="hover:text-cyan">{category.title}</Link> <span aria-hidden="true">/</span>{" "}
        <Link href={`/c/${category.slug}/${topic.slug}/`} className="hover:text-cyan">{topic.title}</Link> <span aria-hidden="true">/</span>{" "}
        <span className="text-ink">{script.file}</span>
      </nav>

      <header className="mt-6 space-y-3">
        <h1 className="break-all text-2xl font-bold text-white sm:text-3xl">{script.file}</h1>
        {script.summary && <p className="max-w-3xl leading-relaxed text-muted">{script.summary}</p>}
        <ul className="flex flex-wrap gap-2 text-xs">
          <li className="rounded border border-line px-2 py-1 uppercase tracking-wider text-cyan">{script.kind}</li>
          <li className="rounded border border-line px-2 py-1 text-ink">{script.language}</li>
          <li className="rounded border border-line px-2 py-1 text-ink">{script.lines} lines</li>
          {script.needsPrivileges && <li className="rounded border border-amber/40 px-2 py-1 text-amber">may need admin rights</li>}
        </ul>
      </header>

      <p className="mt-6 flex items-start gap-3 rounded-md border border-line bg-surface p-4 text-sm text-ink">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber" aria-hidden="true" />
        Run security tools only on systems you own or have written permission to test.
      </p>

      {runnable && (
        <section aria-labelledby="run-heading" className="mt-8">
          <h2 id="run-heading" className="flex items-center gap-2 text-lg font-bold text-white">
            <Terminal className="size-5 text-cyan" aria-hidden="true" /> Run it
          </h2>
          <div className="mt-3 rounded-md border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line px-4 py-2 text-xs text-muted">
              <span>From the repository root, after <code className="text-green">pip install -r tools/requirements.txt</code></span>
              <CopyButton text={command} label="Copy commands" />
            </div>
            <pre className="overflow-x-auto p-4 text-sm text-green">{command}</pre>
          </div>
        </section>
      )}

      <section aria-labelledby="source-heading" className="mt-8">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 id="source-heading" className="text-lg font-bold text-white">Source</h2>
          <div className="flex flex-wrap items-center gap-3">
            <CopyButton text={script.source} label="Copy source" />
            <a href={githubFileUrl(script.path)} className="inline-flex items-center gap-1.5 text-sm text-cyan underline underline-offset-2" target="_blank" rel="noopener noreferrer">
              View on GitHub <ExternalLink className="size-3.5" aria-hidden="true" />
            </a>
          </div>
        </div>
        <div className="code-view mt-3 overflow-hidden rounded-md border border-line bg-surface">
          <pre aria-label={`Source code of ${script.file}`}>
            <code className="hljs" dangerouslySetInnerHTML={{ __html: lines.map((line) => `<span class="line">${line || " "}</span>`).join("") }} />
          </pre>
        </div>
      </section>
    </div>
  );
}
