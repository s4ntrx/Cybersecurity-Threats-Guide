#!/usr/bin/env node
/**
 * Crawl a running site (default http://localhost:3000): fetch every URL in sitemap.xml,
 * follow every internal link found, and fail if anything is not HTTP 200 or a page lacks a title or h1.
 * Usage: npm run build && npm start &   then   npm run check-links [base-url]
 */
const base = (process.argv[2] || "http://localhost:3000").replace(/\/$/, "");
const seen = new Map();
const problems = [];

async function visit(path, from) {
  if (seen.has(path)) return;
  seen.set(path, null);
  const response = await fetch(base + path, { redirect: "manual" });
  seen.set(path, response.status);
  if (response.status !== 200) {
    problems.push(`${response.status} ${path}${from ? `  (linked from ${from})` : ""}`);
    return;
  }
  if (!(response.headers.get("content-type") || "").includes("text/html")) return;
  const html = await response.text();
  if (!/<title>[^<]+<\/title>/.test(html)) problems.push(`no <title>: ${path}`);
  if (!/<h1[\s>]/.test(html)) problems.push(`no <h1>: ${path}`);
  for (const [, href] of html.matchAll(/<a [^>]*href="(\/[^"#?]*)(?:[#?][^"]*)?"/g)) {
    if (!/\.(svg|xml|txt|json|png|ico)$/.test(href)) await visit(href, path);
  }
}

const sitemap = await (await fetch(`${base}/sitemap.xml`)).text();
const routes = [...sitemap.matchAll(/<loc>https?:\/\/[^/<]+(\/[^<]*)<\/loc>/g)].map((m) => m[1]);
for (const route of routes) await visit(route, "sitemap");
for (const asset of ["/search-index.json", "/robots.txt", "/icon.svg"]) await visit(asset, "assets");

console.log(`checked ${seen.size} URLs from ${routes.length} sitemap entries`);
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log("all pages load and have a title and h1");
