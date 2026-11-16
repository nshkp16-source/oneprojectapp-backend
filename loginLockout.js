const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const MAX_TRACKED_ADDRESSES = 10_000;

function retryAfterSeconds(lockedUntil, now) {
  return Math.max(1, Math.ceil((lockedUntil - now) / 1000));
}

export function createLoginLockout(options = {}) {
  const maxAttempts = Number.isSafeInteger(options.maxAttempts) && options.maxAttempts > 0
    ? options.maxAttempts
    : DEFAULT_MAX_ATTEMPTS;
  const windowMs = Number.isSafeInteger(options.windowMs) && options.windowMs > 0
    ? options.windowMs
    : DEFAULT_WINDOW_MS;
  const now = options.now || Date.now;
  const attemptsByAddress = new Map();

  const cleanup = () => {
    const currentTime = now();
    for (const [address, state] of attemptsByAddress) {
      const expiry = state.lockedUntil || state.windowStartedAt + windowMs;
      if (expiry <= currentTime) attemptsByAddress.delete(address);
    }
  };
  const cleanupTimer = setInterval(cleanup, windowMs);
  cleanupTimer.unref?.();

  function addressFor(req) {
    return req.ip || req.socket?.remoteAddress || 'unknown';
  }

  function lockoutResponse(res, lockedUntil, currentTime) {
    const retry = retryAfterSeconds(lockedUntil, currentTime);
    res.set('Retry-After', String(retry));
    return res.status(429).json({
      error: 'Too many failed login attempts.',
      retryAfterSeconds: retry,
    });
  }

  return {
    middleware(req, res, next) {
      const address = addressFor(req);
      const currentTime = now();
      const state = attemptsByAddress.get(address);
      if (state?.lockedUntil > currentTime) {
        return lockoutResponse(res, state.lockedUntil, currentTime);
      }
      if (state && (state.lockedUntil || state.windowStartedAt + windowMs) <= currentTime) {
        attemptsByAddress.delete(address);
      }
      next();
    },

    recordFailure(req, res) {
      const address = addressFor(req);
      const currentTime = now();
      let state = attemptsByAddress.get(address);

      if (state?.lockedUntil > currentTime) {
        return lockoutResponse(res, state.lockedUntil, currentTime);
      }
      if (!state || state.lockedUntil || currentTime - state.windowStartedAt >= windowMs) {
        if (attemptsByAddress.size >= MAX_TRACKED_ADDRESSES) cleanup();
        if (attemptsByAddress.size >= MAX_TRACKED_ADDRESSES) {
          const oldestAddress = attemptsByAddress.keys().next().value;
          if (oldestAddress !== undefined) attemptsByAddress.delete(oldestAddress);
        }
        state = { attempts: 0, windowStartedAt: currentTime };
      }

      state.attempts += 1;
      if (state.attempts >= maxAttempts) {
        state.lockedUntil = currentTime + windowMs;
        attemptsByAddress.set(address, state);
        return lockoutResponse(res, state.lockedUntil, currentTime);
      }
      attemptsByAddress.set(address, state);
      return null;
    },

    recordSuccess(req) {
      attemptsByAddress.delete(addressFor(req));
    },

    close() {
      clearInterval(cleanupTimer);
    },
  };
}
