import SearchBox from "@/components/SearchBox";

export const metadata = { title: "Search", description: "Search every topic and script in the Cybersecurity Threats Guide." };

export default function SearchPage() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-12">
      <h1 className="text-3xl font-bold text-white">Search</h1>
      <p className="mb-8 mt-3 text-muted">Searches topic text, script descriptions and standards IDs such as T1190 or CWE-89. It runs in your browser.</p>
      <SearchBox />
    </div>
  );
}
