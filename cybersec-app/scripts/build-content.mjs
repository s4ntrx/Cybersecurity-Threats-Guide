#!/usr/bin/env node
/**
 * Builds the site's knowledge base from the repository itself.
 *
 *   ../0N-category/**\/README.md   -> categories and topics (rendered markdown, standards mapping, review date)
 *   ../0N-category/**\/*.py etc.   -> scripts (source, summary, run instructions)
 *
 * Output:
 *   content/knowledge.json      committed snapshot, used when the repo folders are not available at build time
 *   public/search-index.json    MiniSearch index loaded by the /search page
 *
 * The script runs before `next dev` and `next build`. If the repository root is not reachable
 * (for example Vercel with "include files outside the Root Directory" switched off) it reuses the snapshot.
 */
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import MiniSearch from "minisearch";
import { searchOptions } from "../lib/search-options.mjs";
import { renderMarkdown, stripEmoji, stripTags } from "./lib/markdown.mjs";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(process.env.CONTENT_REPO_ROOT || path.join(appRoot, ".."));
const snapshotPath = path.join(appRoot, "content", "knowledge.json");
const searchIndexPath = path.join(appRoot, "public", "search-index.json");

const REPO_URL = "https://github.com/s4ntrx/Cybersecurity-Threats-Guide";
const BRANCH = "main";
const CATEGORY_DIR = /^(\d{2})-(.+)$/;
const SCRIPT_EXTENSIONS = new Map([[".py", "python"], [".sh", "bash"], [".json", "json"], [".csv", "text"], [".txt", "text"], [".yml", "yaml"], [".yaml", "yaml"]]);
const SKIP_DIRS = new Set(["__pycache__", "node_modules", ".git", ".venv", "venv"]);
const STRIP_SEGMENTS = new Set(["detection", "prevention", "analysis", "tools", "scripts"]);

const posix = (p) => p.split(path.sep).join("/");
const rel = (abs) => posix(path.relative(repoRoot, abs));
const slugify = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const titleCase = (text) => text.replace(/[-_]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

function gitCommit() {
  if (process.env.VERCEL_GIT_COMMIT_SHA) return process.env.VERCEL_GIT_COMMIT_SHA.slice(0, 7);
  if (process.env.CONTENT_NO_GIT) return null;                       // used when producing the committed snapshot
  try {
    return execSync("git rev-parse --short HEAD", { cwd: repoRoot, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return null;
  }
}

function walk(dir, visit) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, visit);
    else visit(full);
  }
}

const clip = (text, limit = 300) => {
  if (text.length <= limit) return text;
  const cut = text.slice(0, limit);
  const sentence = cut.lastIndexOf(". ");
  return sentence > 120 ? cut.slice(0, sentence + 1) : `${cut.replace(/\s+\S*$/, "")}...`;
};

/** First real prose paragraph: skips code fences, navigation lines ("Back to ..."), link-only lines, tables, lists. */
const firstParagraph = (markdown) => {
  const prose = markdown.replace(/```[\s\S]*?```/g, "").replace(/^#{1,6}\s.*$/gm, "");
  for (const block of prose.split(/\n\s*\n/)) {
    const text = block.trim();
    if (!text || /^(#|>|\||[-*]\s|\d+\.\s|---|<)/.test(text)) continue;
    if (/^\[?.{0,40}\bBack to\b/i.test(text) || /^(\[[^\]]*\]\([^)]*\)[\s|·-]*)+$/.test(text)) continue;
    return clip(stripEmoji(text.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1").replace(/[*_`]/g, "").replace(/\s+/g, " ")));
  }
  return "";
};

function section(markdown, heading) {
  const match = markdown.match(new RegExp(`^##\\s+(?:[^\\w\\n]*\\s)?${heading}\\s*$([\\s\\S]*?)(?=^##\\s|(?![\\s\\S]))`, "mi"));
  return match ? match[1].trim() : "";
}

function parseMapping(markdown) {
  const rows = [];
  for (const line of section(markdown, "Standards mapping").split("\n")) {
    const cells = line.split("|").map((c) => c.trim()).filter(Boolean);
    if (cells.length >= 2 && !/^-+$/.test(cells[0]) && cells[0].toLowerCase() !== "framework") {
      rows.push({ framework: cells[0], value: cells[1].replace(/[*`]/g, "") });
    }
  }
  return rows;
}

function docSummary(source, extension) {
  if (extension === ".py") {
    const doc = source.match(/^(?:\s*(?:#.*)?\n)*\s*[ru]?("""|\'\'\')([\s\S]*?)\1/);
    if (doc) {
      const paragraph = [];
      for (const line of doc[2].trim().split("\n").map((l) => l.trim())) {
        if (!line && paragraph.length) break;
        if (line && !/^Location:/i.test(line)) paragraph.push(line);
      }
      if (paragraph.length) return paragraph.join(" ").slice(0, 320);
    }
    const argparse = source.match(/ArgumentParser\(\s*(?:prog=[^,]+,\s*)?description\s*=\s*(["'])((?:(?!\1).)*)\1/s);
    if (argparse) return argparse[2].trim();
  }
  const comment = source.split("\n").find((l) => /^#\s+\S/.test(l) && !l.startsWith("#!") && !/^#+\s*(coding|-\*-)/.test(l));
  return comment ? comment.replace(/^#+\s+/, "").slice(0, 200) : "";
}

function build() {
  if (!fs.existsSync(repoRoot)) throw new Error(`Repository root not found: ${repoRoot}`);
  const categoryDirs = fs.readdirSync(repoRoot, { withFileTypes: true })
    .filter((e) => e.isDirectory() && CATEGORY_DIR.test(e.name) && fs.existsSync(path.join(repoRoot, e.name)))
    .map((e) => e.name).sort();

  const categories = [];
  const topics = [];
  const scripts = [];

  // ---- pass 1: structure -------------------------------------------------------------
  for (const dirName of categoryDirs) {
    const [, number, slugPart] = dirName.match(CATEGORY_DIR);
    const categoryAbs = path.join(repoRoot, dirName);
    const category = { slug: slugify(slugPart), number, dirName, title: titleCase(slugPart), summary: "", html: "", topics: [], scriptCount: 0 };
    categories.push(category);

    const readmes = new Map();                         // dir relative to category -> README abs path
    const files = [];
    walk(categoryAbs, (abs) => {
      const relToCategory = posix(path.relative(categoryAbs, abs));
      if (path.basename(abs).toLowerCase() === "readme.md") readmes.set(posix(path.dirname(relToCategory)), abs);
      else if (SCRIPT_EXTENSIONS.has(path.extname(abs).toLowerCase()) && !/^requirements/.test(path.basename(abs))) files.push(abs);
    });

    const topicByDir = new Map();
    const ensureTopic = (dirRel, hasReadme) => {
      if (topicByDir.has(dirRel)) return topicByDir.get(dirRel);
      const topic = {
        slug: slugify(path.posix.basename(dirRel)), category: category.slug, dir: posix(path.posix.join(dirName, dirRel)),
        readme: hasReadme ? rel(readmes.get(dirRel)) : null, title: titleCase(path.posix.basename(dirRel)),
        summary: "", lastReviewed: null, status: hasReadme ? "Unspecified" : "No documentation page yet",
        mapping: [], headings: [], html: "", text: "", scripts: [], virtual: !hasReadme,
      };
      if (topics.some((t) => t.category === topic.category && t.slug === topic.slug)) throw new Error(`Duplicate topic slug '${topic.slug}' in ${dirName}`);
      topicByDir.set(dirRel, topic);
      topics.push(topic);
      category.topics.push(topic.slug);
      return topic;
    };

    for (const dirRel of [...readmes.keys()].filter((d) => d !== ".")) ensureTopic(dirRel, true);

    for (const abs of files) {
      const segments = posix(path.dirname(path.relative(categoryAbs, abs))).split("/").filter((s) => s && s !== ".");
      while (segments.length && STRIP_SEGMENTS.has(segments[segments.length - 1])) segments.pop();
      if (!segments.length) { category.scriptCount += 0; continue; }          // loose files in a category root are not topic scripts
      let candidate = segments.join("/");
      let owner = null;
      for (let probe = candidate; probe && probe !== "."; probe = path.posix.dirname(probe)) {
        if (readmes.has(probe)) { owner = ensureTopic(probe, true); break; }
      }
      if (!owner) owner = ensureTopic(candidate, false);

      const extension = path.extname(abs).toLowerCase();
      const source = fs.readFileSync(abs, "utf8");
      const file = path.basename(abs);
      owner.scripts.push({
        file, slug: file.replace(/\./g, "-"), path: rel(abs), language: SCRIPT_EXTENSIONS.get(extension), extension,
        kind: /\/prevention\//.test(rel(abs)) ? "prevention" : /\/detection\//.test(rel(abs)) ? "detection" : "other",
        summary: docSummary(source, extension), lines: source.split("\n").length, needsPrivileges: /\b(root|sudo|administrator|elevated)\b/i.test(source.slice(0, 2500)),
        source, directory: posix(path.dirname(rel(abs))),
      });
    }

    category.readmeAbs = readmes.get(".") || null;
    category._readmes = readmes;
    category._topicByDir = topicByDir;
  }

  // ---- route tables for link resolution -----------------------------------------------
  const routeByFile = new Map();
  const routeByDir = new Map();
  for (const category of categories) {
    routeByDir.set(category.dirName, `/c/${category.slug}/`);
    if (category.readmeAbs) routeByFile.set(rel(category.readmeAbs), `/c/${category.slug}/`);
  }
  for (const topic of topics) {
    const route = `/c/${topic.category}/${topic.slug}/`;
    routeByDir.set(topic.dir, route);
    if (topic.readme) routeByFile.set(topic.readme, route);
    for (const script of topic.scripts) routeByFile.set(script.path, `${route}code/${script.slug}/`);
  }

  const githubUrl = (relativePath, isDir) => `${REPO_URL}/${isDir ? "tree" : "blob"}/${BRANCH}/${relativePath}`;
  const linkResolverFor = (fromAbs) => (href, isImage = false) => {
    if (/^(https?:)\/\//.test(href) || href.startsWith("mailto:")) return { href, external: true };
    if (href.startsWith("#")) return { href };
    const [pathPart, hash] = href.split("#");
    const target = path.resolve(path.dirname(fromAbs), decodeURI(pathPart));
    const targetRel = rel(target);
    const suffix = hash ? `#${hash}` : "";
    if (routeByFile.has(targetRel)) return { href: routeByFile.get(targetRel) + suffix };
    if (routeByDir.has(targetRel)) return { href: routeByDir.get(targetRel) + suffix };
    if (!fs.existsSync(target)) return null;
    if (isImage) return { href: `${REPO_URL}/raw/${BRANCH}/${targetRel}`, external: true };
    return { href: githubUrl(targetRel, fs.statSync(target).isDirectory()), external: true };
  };

  // ---- pass 2: render --------------------------------------------------------------------
  for (const category of categories) {
    if (category.readmeAbs) {
      const markdown = fs.readFileSync(category.readmeAbs, "utf8");
      const { html, title } = renderMarkdown(markdown, linkResolverFor(category.readmeAbs));
      category.title = title || category.title;
      category.summary = ["Overview", "Description", "What it is"].map((h) => firstParagraph(section(markdown, h))).find(Boolean) || "";
      category.html = html;
    }
    delete category.readmeAbs;
    delete category._readmes;
    delete category._topicByDir;
  }

  for (const topic of topics) {
    if (!topic.readme) {
      topic.summary = `Scripts in ${topic.dir}. This folder has no documentation page yet.`;
      continue;
    }
    const abs = path.join(repoRoot, topic.readme);
    const markdown = fs.readFileSync(abs, "utf8");
    const { html, headings, title } = renderMarkdown(markdown, linkResolverFor(abs));
    const meta = markdown.match(/\*\*Last reviewed:\*\*\s*(\d{4}-\d{2}-\d{2})/);
    const status = markdown.match(/\*\*Status:\*\*\s*([^|\n]+)/);
    topic.title = title || topic.title;
    topic.lastReviewed = meta ? meta[1] : null;
    topic.status = status ? status[1].trim() : "Unspecified";
    topic.mapping = parseMapping(markdown);
    topic.summary = ["What it is", "Description", "Overview"].map((h) => firstParagraph(section(markdown, h))).find(Boolean) || firstParagraph(markdown);
    topic.html = html;
    topic.headings = headings;
    topic.text = stripTags(html).replace(/\s+/g, " ").slice(0, 9000);
  }

  for (const category of categories) {
    category.topics = topics.filter((t) => t.category === category.slug).sort((a, b) => Number(a.virtual) - Number(b.virtual) || a.title.localeCompare(b.title)).map((t) => t.slug);
    category.scriptCount = topics.filter((t) => t.category === category.slug).reduce((n, t) => n + t.scripts.length, 0);
    if (!category.summary || /^Algorithms:/.test(category.summary)) {
      const names = category.topics.map((slug) => topics.find((t) => t.category === category.slug && t.slug === slug).title);
      category.summary = `Covers ${names.slice(0, -1).join(", ")} and ${names.at(-1)}.`;
    }
  }
  for (const topic of topics) {
    topic.scripts.sort((a, b) => ({ detection: 0, prevention: 1, other: 2 })[a.kind] - ({ detection: 0, prevention: 1, other: 2 })[b.kind] || a.file.localeCompare(b.file));
    for (const script of topic.scripts) scripts.push({ category: topic.category, topic: topic.slug, ...script });
  }

  return {
    generatedAt: new Date().toISOString(),
    source: { repo: REPO_URL, branch: BRANCH, commit: gitCommit() },
    categories, topics, scripts: scripts.length,
  };
}

function writeSearchIndex(knowledge) {
  const index = new MiniSearch(searchOptions);
  const documents = [];
  const categoryTitle = new Map(knowledge.categories.map((c) => [c.slug, c.title]));
  for (const topic of knowledge.topics) {
    documents.push({
      id: `topic:${topic.category}/${topic.slug}`, kind: "Topic", title: topic.title, summary: topic.summary,
      standards: topic.mapping.map((m) => `${m.framework} ${m.value}`).join(" "), text: topic.text,
      url: `/c/${topic.category}/${topic.slug}/`, category: categoryTitle.get(topic.category),
    });
    for (const script of topic.scripts) {
      documents.push({
        id: `script:${script.path}`, kind: "Script", title: script.file, summary: script.summary, standards: "",
        text: `${topic.title} ${script.kind} ${script.directory}`, url: `/c/${topic.category}/${topic.slug}/code/${script.slug}/`,
        category: categoryTitle.get(topic.category),
      });
    }
  }
  index.addAll(documents);
  fs.mkdirSync(path.dirname(searchIndexPath), { recursive: true });
  fs.writeFileSync(searchIndexPath, JSON.stringify(index));
  return documents.length;
}

function main() {
  const haveRepo = fs.existsSync(repoRoot) && fs.readdirSync(repoRoot).some((n) => CATEGORY_DIR.test(n));
  let knowledge;
  if (haveRepo) {
    knowledge = build();
    fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
    fs.writeFileSync(snapshotPath, JSON.stringify(knowledge));
    console.log(`[content] built from repository at ${repoRoot}`);
  } else if (fs.existsSync(snapshotPath)) {
    knowledge = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
    knowledge.source.commit = gitCommit() ?? knowledge.source.commit;
    fs.writeFileSync(snapshotPath, JSON.stringify(knowledge));
    console.log("[content] repository folders not found; using the committed snapshot content/knowledge.json");
  } else {
    throw new Error("No repository content and no snapshot found. Run `npm run content` from a full checkout.");
  }
  const documents = writeSearchIndex(knowledge);
  const scriptTotal = knowledge.topics.reduce((n, t) => n + t.scripts.length, 0);
  console.log(`[content] ${knowledge.categories.length} categories, ${knowledge.topics.length} topics, ${scriptTotal} scripts, ${documents} search documents`);
}

main();
