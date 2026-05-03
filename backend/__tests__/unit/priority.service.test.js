'use strict';

const { computePriorityScore, getPriorityLabel } = require('../../src/services/priority.service');

describe('computePriorityScore', () => {
  test('all null inputs returns 0', () => {
    expect(computePriorityScore({})).toBe(0);
  });

  test('null string inputs are treated as 0', () => {
    expect(computePriorityScore({ cvssScore: null, epssScore: null, inKev: false })).toBe(0);
  });

  // EPSS contribution (0–40)
  test('EPSS 1.0 contributes exactly 40 points', () => {
    const score = computePriorityScore({ epssScore: 1.0, severity: 'NONE', inKev: false });
    expect(score).toBe(40);
  });

  test('EPSS 0.5 contributes 20 points', () => {
    const score = computePriorityScore({ epssScore: 0.5, severity: 'NONE', inKev: false });
    expect(score).toBe(20);
  });

  test('EPSS 0.0 contributes 0 points', () => {
    const score = computePriorityScore({ epssScore: 0.0, severity: 'NONE', inKev: false });
    expect(score).toBe(0);
  });

  // CVSS severity contribution (0–25)
  test('CRITICAL severity contributes 25 points', () => {
    const score = computePriorityScore({ severity: 'CRITICAL', epssScore: 0, inKev: false });
    expect(score).toBe(25);
  });

  test('CVSS score 9.0 is treated as CRITICAL even if severity says HIGH', () => {
    const score = computePriorityScore({ cvssScore: 9.0, severity: 'HIGH', epssScore: 0, inKev: false });
    expect(score).toBe(25);
  });

  test('HIGH severity contributes 18 points', () => {
    const score = computePriorityScore({ severity: 'HIGH', epssScore: 0, inKev: false });
    expect(score).toBe(18);
  });

  test('MEDIUM severity contributes 10 points', () => {
    const score = computePriorityScore({ severity: 'MEDIUM', epssScore: 0, inKev: false });
    expect(score).toBe(10);
  });

  test('LOW severity contributes 4 points', () => {
    const score = computePriorityScore({ severity: 'LOW', cvssScore: 2.0, epssScore: 0, inKev: false });
    expect(score).toBe(4);
  });

  test('NONE severity contributes 0 CVSS points', () => {
    const score = computePriorityScore({ severity: 'NONE', cvssScore: 0, epssScore: 0, inKev: false });
    expect(score).toBe(0);
  });

  // KEV contribution (flat +25)
  test('KEV status contributes exactly 25 points', () => {
    const score = computePriorityScore({ severity: 'NONE', epssScore: 0, inKev: true });
    expect(score).toBe(25);
  });

  test('KEV-only finding scores at least 25 regardless of CVSS/EPSS', () => {
    const score = computePriorityScore({ inKev: true });
    expect(score).toBeGreaterThanOrEqual(25);
  });

  // Recency (0–10)
  test('CVE published today contributes 10 recency points', () => {
    const published = new Date().toISOString();
    const score = computePriorityScore({ severity: 'NONE', epssScore: 0, inKev: false, publishedAt: published });
    expect(score).toBe(10);
  });

  test('CVE published 60 days ago contributes 6 recency points', () => {
    const d = new Date();
    d.setDate(d.getDate() - 60);
    const score = computePriorityScore({ severity: 'NONE', epssScore: 0, inKev: false, publishedAt: d.toISOString() });
    expect(score).toBe(6);
  });

  test('CVE published 200 days ago contributes 3 recency points', () => {
    const d = new Date();
    d.setDate(d.getDate() - 200);
    const score = computePriorityScore({ severity: 'NONE', epssScore: 0, inKev: false, publishedAt: d.toISOString() });
    expect(score).toBe(3);
  });

  test('CVE published 400 days ago contributes 0 recency points', () => {
    const d = new Date();
    d.setDate(d.getDate() - 400);
    const score = computePriorityScore({ severity: 'NONE', epssScore: 0, inKev: false, publishedAt: d.toISOString() });
    expect(score).toBe(0);
  });

  // Combined / cap
  test('maximum theoretical score is capped at 100', () => {
    const score = computePriorityScore({
      epssScore: 1.0,
      severity: 'CRITICAL',
      cvssScore: 10.0,
      inKev: true,
      publishedAt: new Date().toISOString(),
    });
    expect(score).toBe(100);
  });

  test('score is never negative', () => {
    const score = computePriorityScore({ epssScore: -99, cvssScore: -5, inKev: false });
    expect(score).toBeGreaterThanOrEqual(0);
  });

  // Real-world anchor: log4shell-like CVE
  test('log4shell profile (CRITICAL, high EPSS, KEV, recent) scores ≥ 90', () => {
    const score = computePriorityScore({
      severity: 'CRITICAL',
      cvssScore: 10.0,
      epssScore: 0.97,
      inKev: true,
      publishedAt: new Date().toISOString(),
    });
    expect(score).toBeGreaterThanOrEqual(90);
  });

  test('informational CVE (NONE, zero EPSS, not KEV, old) scores 0', () => {
    const d = new Date();
    d.setFullYear(d.getFullYear() - 5);
    const score = computePriorityScore({
      severity: 'NONE',
      cvssScore: 0,
      epssScore: 0,
      inKev: false,
      publishedAt: d.toISOString(),
    });
    expect(score).toBe(0);
  });
});

describe('getPriorityLabel', () => {
  test('score 80 → CRITICAL PRIORITY', () => {
    expect(getPriorityLabel(80).label).toBe('CRITICAL PRIORITY');
  });

  test('score 79 → HIGH PRIORITY', () => {
    expect(getPriorityLabel(79).label).toBe('HIGH PRIORITY');
  });

  test('score 60 → HIGH PRIORITY', () => {
    expect(getPriorityLabel(60).label).toBe('HIGH PRIORITY');
  });

  test('score 40 → MEDIUM PRIORITY', () => {
    expect(getPriorityLabel(40).label).toBe('MEDIUM PRIORITY');
  });

  test('score 0 → MONITOR', () => {
    expect(getPriorityLabel(0).label).toBe('MONITOR');
  });

  test('returns color for each tier', () => {
    expect(getPriorityLabel(100).color).toBe('red');
    expect(getPriorityLabel(70).color).toBe('orange');
    expect(getPriorityLabel(50).color).toBe('yellow');
    expect(getPriorityLabel(10).color).toBe('blue');
  });
});
