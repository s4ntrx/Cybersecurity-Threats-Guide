"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

export default function CopyButton({ text, label = "Copy" }) {
  const [state, setState] = useState("idle");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
    setTimeout(() => setState("idle"), 2000);
  }

  const Icon = state === "copied" ? Check : Copy;
  return (
    <button
      type="button"
      onClick={copy}
      className="inline-flex items-center gap-1.5 rounded border border-line px-2.5 py-1.5 text-xs text-ink transition-colors hover:border-cyan/60 hover:text-cyan"
    >
      <Icon className="size-3.5" aria-hidden="true" />
      <span aria-live="polite">{state === "copied" ? "Copied" : state === "failed" ? "Copy failed" : label}</span>
    </button>
  );
}
