import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "localhost:3000";
  const protocol =
    requestHeaders.get("x-forwarded-proto") ??
    (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;

  return {
    title: "Mimir — Bitcoin Script Builder",
    description:
      "Offline specification-sheet compiler that normalizes five-key Bitcoin P2WSH policies into verified read-once Miniscript.",
    applicationName: "Mimir",
    robots: { index: false, follow: false, nocache: true },
    openGraph: {
      title: "Mimir — Bitcoin Script Builder",
      description: "read-once p2wsh · repeated visual keys · verified normalization",
      type: "website",
      images: [
        {
          url: `${origin}/og-v2.png`,
          width: 1731,
          height: 909,
          alt: "Mimir read-once P2WSH policy normalizer",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: "Mimir — Bitcoin Script Builder",
      description: "read-once p2wsh · repeated visual keys · verified normalization",
      images: [`${origin}/og-v2.png`],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta
          httpEquiv="Content-Security-Policy"
          content="default-src 'self'; connect-src 'none'; img-src 'self' data:; font-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests"
        />
        <meta name="referrer" content="no-referrer" />
      </head>
      <body>{children}</body>
    </html>
  );
}
