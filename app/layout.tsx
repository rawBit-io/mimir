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
      "Build a fixed five-signer, five-path P2WSH recovery policy from public keys.",
    applicationName: "Mimir",
    robots: { index: false, follow: false, nocache: true },
    openGraph: {
      title: "Mimir — Bitcoin Script Builder",
      description: "5×5 P2WSH recovery · Public keys only · Offline.",
      type: "website",
      images: [
        {
          url: `${origin}/og.png`,
          width: 1733,
          height: 907,
          alt: "Mimir 5×5 P2WSH recovery builder",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: "Mimir — Bitcoin Script Builder",
      description: "5×5 P2WSH recovery · Public keys only · Offline.",
      images: [`${origin}/og.png`],
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
