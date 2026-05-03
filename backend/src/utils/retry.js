'use strict';

/**
 * Retries an async function with exponential back-off.
 *
 * @param {Function} fn           - Async function to call. Receives attempt number (1-based).
 * @param {object}   options
 * @param {number}   options.attempts     - Maximum total attempts (default 3).
 * @param {number}   options.baseDelayMs  - Base delay in ms; doubles each retry (default 1000).
 * @param {Function} options.shouldRetry  - (err) => boolean. Return false to stop immediately.
 *                                          Defaults to: retry on 5xx and network errors,
 *                                          stop on 4xx (client errors — retrying won't help).
 *
 * @throws The last error if all attempts are exhausted or shouldRetry returns false.
 */
async function retry(fn, { attempts = 3, baseDelayMs = 1000, shouldRetry } = {}) {
  const defaultShouldRetry = (err) => {
    const status = err.response?.status;
    if (!status) return true;       // network / timeout error → retry
    if (status >= 500) return true; // 5xx server error → retry
    return false;                   // 4xx client error → no point retrying
  };

  const check = shouldRetry || defaultShouldRetry;
  let lastErr;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      if (!check(err) || attempt === attempts) throw err;
      const delay = baseDelayMs * Math.pow(2, attempt - 1);
      await new Promise((r) => setTimeout(r, delay));
    }
  }

  throw lastErr;
}

module.exports = { retry };
