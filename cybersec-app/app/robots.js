import { siteUrl } from "@/lib/content";

export default function robots() {
  return { rules: { userAgent: "*", allow: "/" }, sitemap: `${siteUrl}/sitemap.xml` };
}
