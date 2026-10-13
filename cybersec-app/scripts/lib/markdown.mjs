import GithubSlugger from "github-slugger";
import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import json from "highlight.js/lib/languages/json";
import python from "highlight.js/lib/languages/python";
import yaml from "highlight.js/lib/languages/yaml";
import { Marked } from "marked";

hljs.registerLanguage("python", python);
hljs.registerLanguage("bash", bash);
hljs.registerLanguage("json", json);
hljs.registerLanguage("yaml", yaml);

const EMOJI = /[\p{Extended_Pictographic}\uFE0F\u200D]/gu;
export const stripEmoji = (text) => text.replace(EMOJI, "").replace(/\s{2,}/g, " ").trim();

export const escapeHtml = (text) =>
  text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export function highlightCode(source, language) {
  const name = (language || "").split(/\s/)[0].toLowerCase();
  const alias = { sh: "bash", shell: "bash", py: "python", yml: "yaml" }[name] || name;
  if (alias && hljs.getLanguage(alias)) {
    return { html: hljs.highlight(source, { language: alias, ignoreIllegals: true }).value, language: alias };
  }
  return { html: escapeHtml(source), language: alias || "text" };
}

export const stripTags = (html) => html.replace(/<[^>]*>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'");

/**
 * Render repository markdown to safe HTML.
 * Raw HTML in the markdown is escaped (never injected), headings get stable ids, relative links
 * are mapped to site routes by `resolveLink`, and code fences are syntax highlighted.
 */
export function renderMarkdown(markdown, resolveLink) {
  const slugger = new GithubSlugger();
  const headings = [];
  let title = null;

  const marked = new Marked({ gfm: true, breaks: false });
  marked.use({
    renderer: {
      html: ({ text }) => escapeHtml(text),
      heading({ tokens, depth }) {
        const inline = this.parser.parseInline(tokens);
        const text = stripEmoji(stripTags(inline));
        if (depth === 1 && title === null) {
          title = text;
          return "";
        }
        const id = slugger.slug(text);
        if (depth <= 3) headings.push({ id, text, depth });
        return `<h${depth} id="${id}">${stripEmoji(inline)}</h${depth}>\n`;
      },
      code({ text, lang }) {
        const { html, language } = highlightCode(text, lang);
        const label = language === "mermaid" ? "diagram source" : language;
        return `<pre data-language="${escapeHtml(label)}"><code class="hljs">${html}</code></pre>\n`;
      },
      link({ href, title: linkTitle, tokens }) {
        const inner = this.parser.parseInline(tokens);
        const target = resolveLink(href);
        if (!target) return `<span class="missing-link" title="Not available yet">${inner}</span>`;
        const attrs = target.external ? ' target="_blank" rel="noopener noreferrer"' : "";
        const titleAttr = linkTitle ? ` title="${escapeHtml(linkTitle)}"` : "";
        return `<a href="${escapeHtml(target.href)}"${titleAttr}${attrs}>${inner}</a>`;
      },
      image({ href, text }) {
        const target = resolveLink(href, true);
        return target ? `<img src="${escapeHtml(target.href)}" alt="${escapeHtml(text || "")}" loading="lazy" />` : "";
      },
      table(token) {
        const header = token.header.map((cell, i) => `<th${token.align[i] ? ` align="${token.align[i]}"` : ""}>${this.parser.parseInline(cell.tokens)}</th>`).join("");
        const rows = token.rows
          .map((row) => `<tr>${row.map((cell, i) => `<td${token.align[i] ? ` align="${token.align[i]}"` : ""}>${this.parser.parseInline(cell.tokens)}</td>`).join("")}</tr>`)
          .join("\n");
        return `<div class="table-wrap"><table><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table></div>\n`;
      },
    },
  });

  const html = marked.parse(markdown);
  return { html, headings, title };
}
