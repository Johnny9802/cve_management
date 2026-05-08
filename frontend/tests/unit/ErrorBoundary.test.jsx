import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ErrorBoundary from '../../src/components/Shared/ErrorBoundary';

function Boom() {
  throw new Error('fake render error');
}

describe('ErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <p>healthy child</p>
      </ErrorBoundary>,
    );
    expect(screen.getByText('healthy child')).toBeInTheDocument();
  });

  it('renders fallback alert when child throws and reset restores it', async () => {
    // React logs the error to console.error during the throw — silence it
    // so the test output stays clean.
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    function Wrapper() {
      // Toggle controls whether Boom is mounted — unmounting it lets the
      // boundary reset cleanly when "Riprova" fires.
      const [crash, setCrash] = require('react').useState(true);
      return (
        <div>
          <button data-testid="fix" onClick={() => setCrash(false)}>fix</button>
          <ErrorBoundary>
            {crash ? <Boom /> : <span>recovered</span>}
          </ErrorBoundary>
        </div>
      );
    }

    render(<Wrapper />);
    expect(screen.getByRole('alert')).toHaveTextContent(/errore/i);

    // Clicking "fix" re-renders the parent with a healthy child;
    // pressing Riprova clears the boundary state.
    await userEvent.click(screen.getByTestId('fix'));
    await userEvent.click(screen.getByRole('button', { name: /riprova/i }));
    expect(screen.getByText('recovered')).toBeInTheDocument();

    errSpy.mockRestore();
  });

  it('calls onError with the captured error', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const onError = vi.fn();
    render(
      <ErrorBoundary onError={onError}>
        <Boom />
      </ErrorBoundary>,
    );
    expect(onError).toHaveBeenCalledWith(
      expect.any(Error),
      expect.objectContaining({ componentStack: expect.any(String) }),
    );
    errSpy.mockRestore();
  });
});
