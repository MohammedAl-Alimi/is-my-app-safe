import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Is My App Safe? — passive web security scanner",
  description:
    "Enter a URL and get an instant, passive security surface check — headers, exposed files, leaked secrets, CORS, TLS, DMARC — mapped to the Agent Security Playbook.",
  openGraph: {
    title: "Is My App Safe?",
    description: "Instant passive security surface check for any web app.",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
