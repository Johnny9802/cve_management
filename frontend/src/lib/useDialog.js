'use client';
import { useEffect, useRef } from 'react';

/**
 * Modal / drawer accessibility helpers.
 *
 * useEscape(onClose) — calls onClose when Escape is pressed.
 * useFocusTrap(active) — returns a ref that, when applied to a container,
 *   constrains Tab navigation inside it and restores focus on unmount.
 */

export function useEscape(onClose) {
  useEffect(() => {
    if (!onClose) return undefined;
    const handler = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);
}

const FOCUSABLE_SEL = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

export function useFocusTrap(active) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!active) return undefined;
    const container = containerRef.current;
    const opener = document.activeElement;

    // Focus the first focusable element on mount.
    const focusables = container?.querySelectorAll(FOCUSABLE_SEL) || [];
    const first = focusables[0];
    if (first) first.focus();

    function handler(e) {
      if (e.key !== 'Tab') return;
      const items = container?.querySelectorAll(FOCUSABLE_SEL);
      if (!items || !items.length) return;
      const firstEl = items[0];
      const lastEl = items[items.length - 1];
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    }
    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      if (opener && typeof opener.focus === 'function') {
        opener.focus();
      }
    };
  }, [active]);

  return containerRef;
}
