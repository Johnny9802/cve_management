// Server-component wrapper. Marked dynamic because the client uses
// AppShell + per-render API calls and we never want this prerendered.
import RemediationPage from './RemediationPage';

export const dynamic = 'force-dynamic';

export default function Page() {
  return <RemediationPage />;
}
