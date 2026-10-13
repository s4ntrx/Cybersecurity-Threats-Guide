import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const knowledge = JSON.parse(fs.readFileSync(path.join(root, "content", "knowledge.json"), "utf8"));

test("the knowledge base covers six categories and every topic has a category", () => {
  assert.equal(knowledge.categories.length, 6);
  const known = new Set(knowledge.categories.map((c) => c.slug));
  for (const topic of knowledge.topics) assert.ok(known.has(topic.category), topic.slug);
});

test("topic slugs are unique within a category and script slugs within a topic", () => {
  const topicKeys = knowledge.topics.map((t) => `${t.category}/${t.slug}`);
  assert.equal(new Set(topicKeys).size, topicKeys.length);
  for (const topic of knowledge.topics) {
    const slugs = topic.scripts.map((s) => s.slug);
    assert.equal(new Set(slugs).size, slugs.length, topic.slug);
  }
});

test("every topic has a title and a summary, and category summaries are real sentences", () => {
  for (const topic of knowledge.topics) {
    assert.ok(topic.title.length > 1, topic.slug);
    assert.ok(topic.summary.length > 20, `${topic.slug} has no summary`);
  }
  for (const category of knowledge.categories) assert.ok(category.summary.length > 20 && !/^Back to/i.test(category.summary), category.slug);
});

test("rendered pages contain no raw script tags and no unresolved links", () => {
  for (const item of [...knowledge.topics, ...knowledge.categories]) {
    assert.ok(!/<script/i.test(item.html), `${item.slug}: script tag in html`);
    assert.ok(!item.html.includes("missing-link"), `${item.slug}: link to a file that does not exist`);
  }
});

test("internal links point at pages that exist", () => {
  const routes = new Set(["/"]);
  for (const c of knowledge.categories) routes.add(`/c/${c.slug}/`);
  for (const t of knowledge.topics) {
    routes.add(`/c/${t.category}/${t.slug}/`);
    for (const s of t.scripts) routes.add(`/c/${t.category}/${t.slug}/code/${s.slug}/`);
  }
  for (const item of [...knowledge.topics, ...knowledge.categories]) {
    for (const [, href] of item.html.matchAll(/<a href="(\/[^"#]*)/g)) assert.ok(routes.has(href), `${item.slug} links to ${href}`);
  }
});

test("topics written from the template carry a review date and a standards mapping", () => {
  const dated = knowledge.topics.filter((t) => t.lastReviewed);
  assert.ok(dated.length >= 12);
  for (const topic of dated) assert.ok(topic.mapping.length >= 4, `${topic.slug} mapping`);
});

test("scripts keep their source and a summary", () => {
  for (const topic of knowledge.topics) {
    for (const script of topic.scripts.filter((s) => s.extension === ".py")) {
      assert.ok(script.source.length > 50, script.file);
      assert.ok(script.summary.length > 5, `${script.file} has no docstring summary`);
    }
  }
});
