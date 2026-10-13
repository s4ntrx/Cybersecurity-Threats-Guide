import Link from "next/link";

export const metadata = { title: "Page not found" };

export default function NotFound() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-24 text-center">
      <p className="text-sm font-bold uppercase tracking-[0.2em] text-red">Error 404</p>
      <h1 className="mt-4 text-4xl font-bold text-white">That page does not exist</h1>
      <p className="mt-4 text-muted">It may have been renamed in the repository. Try the search or start from the home page.</p>
      <div className="mt-8 flex justify-center gap-3">
        <Link href="/" className="rounded-md bg-cyan px-5 py-3 text-sm font-bold text-bg transition-colors hover:bg-white">Home</Link>
        <Link href="/search/" className="rounded-md border border-line px-5 py-3 text-sm font-bold text-white transition-colors hover:border-cyan/60">Search</Link>
      </div>
    </div>
  );
}
