"use client";

import Link from "next/link";
import MiniSearch from "minisearch";
import { Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { searchOptions } from "@/lib/search-options.mjs";

const suggestions = ["SQL injection", "T1190", "phishing", "key rotation", "CWE-352", "ransomware backup"];

export default function SearchBox() {
  const [index, setIndex] = useState(null);
  const [error, setError] = useState(false);
  const [query, setQuery] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    const initial = new URLSearchParams(window.location.search).get("q");
    if (initial) setQuery(initial);
    inputRef.current?.focus();
    fetch("/search-index.json")
      .then((response) => (response.ok ? response.text() : Promise.reject(new Error(String(response.status)))))
      .then((json) => setIndex(MiniSearch.loadJSON(json, searchOptions)))
      .catch(() => setError(true));
  }, []);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (query) url.searchParams.set("q", query);
    else url.searchParams.delete("q");
    window.history.replaceState(null, "", url);
  }, [query]);

  const results = useMemo(() => (index && query.trim().length > 1 ? index.search(query.trim()).slice(0, 25) : []), [index, query]);

  return (
    <div>
      <label htmlFor="site-search" className="sr-only">Search topics and scripts</label>
      <div className="flex items-center gap-3 rounded-md border border-line bg-surface px-4 focus-within:border-cyan">
        <Search className="size-5 shrink-0 text-muted" aria-hidden="true" />
        <input
          id="site-search"
          ref={inputRef}
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search topics, scripts, CWE or ATT&CK IDs"
          autoComplete="off"
          className="w-full bg-transparent py-3.5 text-base text-white placeholder:text-muted focus:outline-none"
        />
      </div>

      <div className="mt-6" aria-live="polite">
        {error && <p className="text-sm text-red">The search index could not be loaded. Refresh the page to try again.</p>}
        {!error && !index && <p className="text-sm text-muted">Loading the search index...</p>}
        {index && query.trim().length <= 1 && (
          <div className="space-y-3">
            <p className="text-sm text-muted">Try one of these:</p>
            <ul className="flex flex-wrap gap-2">
              {suggestions.map((text) => (
                <li key={text}>
                  <button type="button" onClick={() => setQuery(text)} className="rounded border border-line px-3 py-1.5 text-sm text-ink transition-colors hover:border-cyan/60 hover:text-cyan">
                    {text}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        {index && query.trim().length > 1 && (
          <>
            <p className="mb-4 text-sm text-muted">{results.length === 0 ? "No matches. Try fewer or different words." : `${results.length} result${results.length === 1 ? "" : "s"}`}</p>
            <ul className="space-y-3">
              {results.map((result) => (
                <li key={result.id}>
                  <Link href={result.url} className="block rounded-md border border-line bg-surface p-4 transition-colors hover:border-cyan/60">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
                      <span className="rounded border border-line px-1.5 py-0.5 font-bold uppercase tracking-wider text-cyan">{result.kind}</span>
                      <span>{result.category}</span>
                    </div>
                    <p className="mt-1.5 font-bold text-white">{result.title}</p>
                    {result.summary && <p className="mt-1 line-clamp-2 text-sm text-muted">{result.summary}</p>}
                  </Link>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </div>
  );
}
