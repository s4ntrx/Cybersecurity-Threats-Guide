import Link from "next/link";
import { categories, formatDate, generatedAt, repoUrl, source } from "@/lib/content";

export default function SiteFooter() {
  return (
    <footer className="mt-24 border-t border-line">
      <div className="mx-auto grid max-w-6xl gap-8 px-4 py-10 text-sm text-muted md:grid-cols-3">
        <div className="space-y-2">
          <p className="font-bold text-white">Cybersecurity Threats Guide</p>
          <p>Educational material for defenders. Only test systems you own or have written permission to test.</p>
        </div>
        <nav aria-label="Footer categories">
          <p className="mb-2 font-bold text-white">Categories</p>
          <ul className="space-y-1.5">
            {categories.map((category) => (
              <li key={category.slug}><Link href={`/c/${category.slug}/`} className="hover:text-cyan">{category.title}</Link></li>
            ))}
          </ul>
        </nav>
        <div className="space-y-2">
          <p className="font-bold text-white">Source</p>
          <p>
            Every page is generated from the files in the{" "}
            <a href={repoUrl} className="text-cyan underline underline-offset-2" target="_blank" rel="noopener noreferrer">GitHub repository</a>.
          </p>
          <p>
            Content built {formatDate(generatedAt)}
            {source.commit ? <> from commit <code className="text-ink">{source.commit}</code></> : null}.
          </p>
          <p>MIT licensed.</p>
        </div>
      </div>
    </footer>
  );
}
