# Cybersecurity Threats Guide: website

A Next.js site that publishes the guide. **Every page is generated from this repository's own files**, so the site cannot drift from the code:

| Source in the repo | Becomes on the site |
|---|---|
| `0N-category/README.md` | a category page (`/c/<category>/`) |
| `0N-category/**/<topic>/README.md` | a topic page (`/c/<category>/<topic>/`) with a table of contents |
| the "Standards mapping" table in a topic README | standards chips and the `/standards/` index (OWASP, ATT&CK, CWE, CAPEC) |
| `**/detection/*.py`, `**/prevention/*.py` and other scripts | a code page with highlighted source and run instructions |
| all of the above | the in-browser search (`/search/`) |

Add or edit a README or script in the repository and the site picks it up on the next build. Nothing is hard-coded: the counts on the home page, the "recently reviewed" list and the standards index are all computed.

## Run it locally

Requires Node.js 22.

```bash
cd cybersec-app
npm install
npm run dev        # http://localhost:3000, regenerates content first
```

Other commands:

```bash
npm run content       # rebuild content/knowledge.json and the search index from the repo
npm test              # content checks (summaries, links, escaping, slugs)
npm run build         # production build (runs `content` first)
npm start             # serve the production build
npm run check-links   # with the site running: crawl every page and link
```


## How the content build works

`scripts/build-content.mjs` runs before `dev` and `build`:

1. Finds the numbered category folders.
2. Treats every folder with a `README.md` as a topic. A folder with scripts but no README becomes a "No documentation page yet" topic so its scripts are still reachable.
3. Renders each README to HTML. Raw HTML in markdown is **escaped, never injected**; relative links are rewritten to site routes (or to GitHub when the target is not a page); code fences are syntax highlighted.
4. Reads the review date, status and standards table from the topic README (see `TOPIC_TEMPLATE.md` in the repo root).
5. Writes `content/knowledge.json` and `public/search-index.json`.

## Project layout

```
app/            routes (home, category, topic, code, search, standards, sitemap, robots)
components/     header, footer, cards, search box, copy button
lib/            content access helpers and shared search options
scripts/        content builder, link crawler, tests
content/        generated knowledge snapshot (committed on purpose)
```

No external fonts, scripts or trackers are loaded. Responses carry security headers (HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
