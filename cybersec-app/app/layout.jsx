import "./globals.css";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import { siteUrl } from "@/lib/content";

const description = "Learn how common cyber attacks work and how to detect and prevent them, with working Python scripts for every topic. Built directly from the open-source repository.";

export const metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: "Cybersecurity Threats Guide", template: "%s | Cybersecurity Threats Guide" },
  description,
  openGraph: { title: "Cybersecurity Threats Guide", description, type: "website", siteName: "Cybersecurity Threats Guide" },
  twitter: { card: "summary", title: "Cybersecurity Threats Guide", description },
};

export const viewport = { themeColor: "#020608", colorScheme: "dark" };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-bg font-mono text-ink antialiased">
        <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-cyan focus:px-3 focus:py-2 focus:text-bg">
          Skip to content
        </a>
        <SiteHeader />
        <main id="main">{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}
