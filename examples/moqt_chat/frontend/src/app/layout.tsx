import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MOQT Chat",
  description: "Media over QUIC Transport chat example",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
