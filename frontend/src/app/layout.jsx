import './globals.css';

export const metadata = { title: 'CVE Management', description: 'Track CVEs for your products' };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
