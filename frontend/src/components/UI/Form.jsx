'use client';

/**
 * Shared form primitives (Sprint 3 — S3.4).
 *
 * Until now every page that needed a form built its own labelled
 * input + error display + dark-theme styling. The duplication made
 * S3.5 (a11y label/htmlFor audit) painful — one fix per consumer
 * instead of one fix per primitive — so we extract the three primitives
 * we actually need today: TextField, Select, Textarea.
 *
 * Each primitive:
 *   * forces an `id` so <label htmlFor> always points to a real input
 *     (closes FE-14 from the production-readiness review),
 *   * surfaces an inline `error` slot tied to the input via
 *     aria-describedby, so screen readers announce the validation
 *     message when focus enters the field,
 *   * accepts a `hint` slot for help text rendered below the input.
 *
 * Styling matches the dark theme already used by webhooks/inventory
 * forms — replacing those inline blocks with these primitives is a
 * mechanical follow-up.
 */
import { forwardRef, useId } from 'react';

const baseInputCls =
  'w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white ' +
  'focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 ' +
  'disabled:opacity-60 disabled:cursor-not-allowed';

function ariaDescribedBy(error, hint) {
  const ids = [];
  if (error) ids.push(`${error}-err`);
  if (hint) ids.push(`${hint}-hint`);
  return ids.length ? ids.join(' ') : undefined;
}

function FieldShell({ id, label, hint, error, required, children }) {
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-xs text-gray-400">
        {label}
        {required && <span className="text-red-400 ml-1" aria-hidden>*</span>}
      </label>
      {children}
      {hint && (
        <p id={`${id}-hint`} className="text-[11px] text-gray-500">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-err`} role="alert" className="text-[11px] text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}

export const TextField = forwardRef(function TextField(
  { id, label, hint, error, required, type = 'text', className = '', ...rest },
  ref,
) {
  const reactId = useId();
  const fieldId = id || reactId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error} required={required}>
      <input
        ref={ref}
        id={fieldId}
        type={type}
        required={required}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={ariaDescribedBy(error && fieldId, hint && fieldId)}
        className={`${baseInputCls} ${className}`.trim()}
        {...rest}
      />
    </FieldShell>
  );
});

export const Select = forwardRef(function Select(
  { id, label, hint, error, required, children, className = '', ...rest },
  ref,
) {
  const reactId = useId();
  const fieldId = id || reactId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error} required={required}>
      <select
        ref={ref}
        id={fieldId}
        required={required}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={ariaDescribedBy(error && fieldId, hint && fieldId)}
        className={`${baseInputCls} ${className}`.trim()}
        {...rest}
      >
        {children}
      </select>
    </FieldShell>
  );
});

export const Textarea = forwardRef(function Textarea(
  { id, label, hint, error, required, rows = 4, className = '', ...rest },
  ref,
) {
  const reactId = useId();
  const fieldId = id || reactId;
  return (
    <FieldShell id={fieldId} label={label} hint={hint} error={error} required={required}>
      <textarea
        ref={ref}
        id={fieldId}
        rows={rows}
        required={required}
        aria-invalid={Boolean(error) || undefined}
        aria-describedby={ariaDescribedBy(error && fieldId, hint && fieldId)}
        className={`${baseInputCls} resize-y min-h-[6rem] ${className}`.trim()}
        {...rest}
      />
    </FieldShell>
  );
});
