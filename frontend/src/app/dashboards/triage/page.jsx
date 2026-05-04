// Server component wrapper. Wraps the client TriagePage in a Suspense
// boundary so Next 14 can render `useSearchParams()` without bailing
// out the whole route.
import { Suspense } from 'react';
import TriagePage from './TriagePage';

// Force dynamic rendering: the page reads live data + URL state.
export const dynamic = 'force-dynamic';

export default function Page() {
  return (
    <Suspense fallback={null}>
      <TriagePage />
    </Suspense>
  );
}
