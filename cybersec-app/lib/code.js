import { highlightCode } from "../scripts/lib/markdown.mjs";

/** Split highlighted HTML into one string per source line, closing and reopening spans at line breaks. */
export function highlightedLines(source, language) {
  const { html } = highlightCode(source, language);
  const lines = [];
  const open = [];
  let current = "";
  for (const token of html.split(/(<span[^>]*>|<\/span>|\n)/)) {
    if (token === "\n") {
      lines.push(current + "</span>".repeat(open.length));
      current = open.join("");
    } else {
      if (token.startsWith("<span")) open.push(token);
      else if (token === "</span>") open.pop();
      current += token;
    }
  }
  lines.push(current + "</span>".repeat(open.length));
  if (lines.length > 1 && lines.at(-1) === "") lines.pop();
  return lines;
}
