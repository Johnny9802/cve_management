import '@testing-library/jest-dom/vitest';

// recharts (and a few other libs) read window.matchMedia and
// ResizeObserver during render. jsdom doesn't provide either, so we
// stub them here. Tests that actually need to exercise matchMedia can
// override the stub before mounting.
if (typeof window !== 'undefined') {
  if (!window.matchMedia) {
    window.matchMedia = (query) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    });
  }
  if (!window.ResizeObserver) {
    window.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
}
