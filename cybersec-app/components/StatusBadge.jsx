const styles = {
  reviewed: "border-green/40 text-green",
  draft: "border-amber/40 text-amber",
  none: "border-line text-muted",
};

export function statusKind(status) {
  if (/^reviewed/i.test(status)) return ["reviewed", "Reviewed"];
  if (/^draft/i.test(status)) return ["draft", "Draft"];
  if (/^no documentation/i.test(status)) return ["none", "No page yet"];
  return ["none", "Not reviewed"];
}

export default function StatusBadge({ status }) {
  const [kind, label] = statusKind(status);
  return <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[0.7rem] font-bold uppercase tracking-wider ${styles[kind]}`}>{label}</span>;
}
