import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  SeverityBadge,
  KevBadge,
  PriorityScoreBadge,
  FindingStatusBadge,
} from '../../src/components/UI/Badge';

describe('Badge family', () => {
  it('SeverityBadge prints the severity label', () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText(/critical/i)).toBeInTheDocument();
  });

  it('KevBadge renders only when active', () => {
    const { rerender, container } = render(<KevBadge active={false} />);
    expect(container.textContent).not.toMatch(/kev/i);

    rerender(<KevBadge active />);
    expect(screen.getByText(/kev/i)).toBeInTheDocument();
  });

  it('PriorityScoreBadge accepts numeric or string score', () => {
    const { rerender } = render(<PriorityScoreBadge score={92} />);
    expect(screen.getByText(/92/)).toBeInTheDocument();
    rerender(<PriorityScoreBadge score="50" />);
    expect(screen.getByText(/50/)).toBeInTheDocument();
  });

  it('FindingStatusBadge renders all FSM statuses', () => {
    for (const s of [
      'open', 'in_review', 'planned', 'remediated',
      'closed', 'false_positive', 'accepted_risk',
    ]) {
      const { unmount } = render(<FindingStatusBadge status={s} />);
      // The badge should at minimum render the status label (with _ → space).
      const text = s.replace('_', ' ');
      expect(screen.getByText(new RegExp(text, 'i'))).toBeInTheDocument();
      unmount();
    }
  });
});
