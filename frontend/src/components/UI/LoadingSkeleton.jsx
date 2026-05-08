'use client';

/**
 * Loading skeletons (Sprint 3 — S3.4 / S3.9).
 *
 * One small primitive component plus three variants tuned to the
 * actual UI surfaces in the platform:
 *
 *   <Skeleton />         — single shimmering bar, opt-in width/height.
 *   <SkeletonRows />     — N <tr>-shaped placeholders for tables.
 *   <SkeletonCard />     — header + 3 lines block, used on dashboards.
 *
 * Honors `prefers-reduced-motion` (the shimmer animation is disabled
 * in globals.css). Each skeleton has role="status" + aria-live so
 * AT users hear "Caricamento" and the on-screen content is announced
 * once it lands.
 */

export function Skeleton({ className = '', label }) {
  return (
    <span
      role="status"
      aria-live="polite"
      aria-label={label || 'Caricamento'}
      className={
        'block bg-gray-800/60 rounded animate-pulse ' +
        (className || 'h-4 w-full')
      }
    />
  );
}

export function SkeletonRows({ rows = 5, cols = 6 }) {
  return (
    <>
      {Array.from({ length: rows }, (_, i) => (
        <tr key={i} className="animate-pulse">
          {Array.from({ length: cols }, (_, j) => (
            <td key={j} className="px-3 py-2">
              <span className="block h-3 w-full bg-gray-800/60 rounded" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

export function SkeletonCard({ className = '' }) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Caricamento"
      className={
        'bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-2 animate-pulse ' +
        className
      }
    >
      <div className="h-4 w-1/3 bg-gray-800/60 rounded" />
      <div className="h-3 w-full bg-gray-800/60 rounded" />
      <div className="h-3 w-5/6 bg-gray-800/60 rounded" />
      <div className="h-3 w-4/6 bg-gray-800/60 rounded" />
    </div>
  );
}
