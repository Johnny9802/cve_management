import './globals.css';
import SentryBoot from '../components/Shared/SentryBoot';

export const metadata = { title: 'CVE Management', description: 'Track CVEs for your products' };

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        <SentryBoot />
        {children}
      </body>
    </html>
  );
}
