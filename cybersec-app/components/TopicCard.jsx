import Link from "next/link";
import { FileCode2 } from "lucide-react";
import StatusBadge from "./StatusBadge";
import { formatDate, identifiersOf } from "@/lib/content";

export default function TopicCard({ topic }) {
  const ids = identifiersOf(topic).filter((i) => i.kind !== "CAPEC").slice(0, 3);
  return (
    <Link
      href={`/c/${topic.category}/${topic.slug}/`}
      className="group flex h-full flex-col gap-3 rounded-md border border-line bg-surface p-5 transition-colors hover:border-cyan/60"
    >
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-base font-bold text-white group-hover:text-cyan">{topic.title}</h3>
        <StatusBadge status={topic.status} />
      </div>
      <p className="line-clamp-3 text-sm leading-relaxed text-muted">{topic.summary}</p>
      {ids.length > 0 && (
        <ul className="flex flex-wrap gap-2" aria-label="Standards">
          {ids.map((item) => (
            <li key={item.id} className="rounded border border-line px-2 py-0.5 text-xs text-ink">{item.id}</li>
          ))}
        </ul>
      )}
      <div className="mt-auto flex items-center justify-between pt-1 text-xs text-muted">
        <span className="inline-flex items-center gap-1.5">
          <FileCode2 className="size-3.5" aria-hidden="true" />
          {topic.scripts.length} {topic.scripts.length === 1 ? "script" : "scripts"}
        </span>
        <span>{topic.lastReviewed ? `Reviewed ${formatDate(topic.lastReviewed)}` : "Not yet reviewed"}</span>
      </div>
    </Link>
  );
}
