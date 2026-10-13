import Link from "next/link";
import { ShieldCheck, Search } from "lucide-react";
import { categories, repoUrl } from "@/lib/content";

const navLink = "rounded px-3 py-2 text-sm text-ink transition-colors hover:text-cyan";

export default function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-bg/90 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
        <Link href="/" className="flex items-center gap-2.5 font-bold text-white">
          <ShieldCheck className="size-6 text-cyan" aria-hidden="true" />
          <span className="hidden sm:inline">Cybersecurity Threats Guide</span>
          <span className="sm:hidden">Threats Guide</span>
        </Link>
        <nav aria-label="Main" className="flex items-center gap-1">
          <Link href="/standards/" className={navLink}>Standards</Link>
          <Link href="/search/" className={`${navLink} inline-flex items-center gap-1.5`}>
            <Search className="size-4" aria-hidden="true" />
            Search
          </Link>
          <a href={repoUrl} className={navLink} target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
      </div>
      <nav aria-label="Categories" className="border-t border-line/60">
        <ul className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4 py-1.5 text-xs">
          {categories.map((category) => (
            <li key={category.slug} className="shrink-0">
              <Link href={`/c/${category.slug}/`} className="block rounded px-2.5 py-1.5 text-muted transition-colors hover:text-cyan">
                <span className="mr-1.5 text-cyan/70">{category.number}</span>
                {category.title}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
    </header>
  );
}
