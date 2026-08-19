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
    title: "MIMIR // POLICY TERMINAL",
    description:
      "Compose K-of-N Bitcoin vault policies from direct public keys in a one-page offline terminal.",
    applicationName: "Mimir",
    robots: { index: false, follow: false, nocache: true },
    openGraph: {
      title: "MIMIR // POLICY TERMINAL",
      description: "Compose K-of-N vaults · Public keys only · Offline by design.",
      type: "website",
      images: [
        {
          url: `${origin}/og.png`,
          width: 1731,
          height: 909,
          alt: "Mimir public-key Bitcoin policy terminal",
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: "MIMIR // POLICY TERMINAL",
      description: "Compose K-of-N vaults · Public keys only · Offline by design.",
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
