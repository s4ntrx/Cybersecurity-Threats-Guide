/** Shared by the build script (which creates the index) and the browser (which loads it). */
export const searchOptions = {
  fields: ["title", "summary", "standards", "text"],
  storeFields: ["title", "summary", "url", "kind", "category"],
  searchOptions: {
    boost: { title: 4, standards: 3, summary: 2 },
    prefix: true,
    fuzzy: 0.2,
    combineWith: "AND",
  },
};
