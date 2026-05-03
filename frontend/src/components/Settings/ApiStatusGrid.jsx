'use client';
import ApiStatusCard from './ApiStatusCard';

const SERVICE_ORDER = ['nvd', 'circl', 'epss', 'kev', 'redis', 'database'];

function SkeletonCard() {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-3 animate-pulse">
      <div className="flex justify-between">
        <div className="flex gap-2 items-center">
          <div className="w-6 h-6 bg-gray-700 rounded-full" />
          <div className="space-y-1">
            <div className="w-16 h-3 bg-gray-700 rounded" />
            <div className="w-24 h-2 bg-gray-800 rounded" />
          </div>
        </div>
        <div className="w-14 h-5 bg-gray-700 rounded" />
      </div>
      <div className="flex justify-between items-end">
        <div className="w-20 h-7 bg-gray-700 rounded" />
        <div className="w-12 h-7 bg-gray-700 rounded" />
      </div>
    </div>
  );
}

export default function ApiStatusGrid({ statuses, onTest, loading }) {
  if (loading && !statuses) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {SERVICE_ORDER.map((id) => <SkeletonCard key={id} />)}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {SERVICE_ORDER.map((id) => (
        <ApiStatusCard
          key={id}
          id={id}
          data={statuses?.[id]}
          onTest={onTest}
        />
      ))}
    </div>
  );
}
