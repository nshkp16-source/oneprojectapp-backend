import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createServer } from 'node:http';
import { createLoginLockout } from './loginLockout.js';

test('fifth failed login locks the IP for a full five minutes', async t => {
  let currentTime = 1_000_000;
  const lockout = createLoginLockout({ maxAttempts: 5, windowMs: 300_000, now: () => currentTime });
  const app = express();
  app.use('/login', lockout.middleware);
  app.post('/login', (req, res) => {
    const response = lockout.recordFailure(req, res);
    if (response) return response;
    return res.status(401).json({ error: 'Invalid password.' });
  });
  const server = createServer(app);

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    lockout.close();
    return new Promise(resolve => server.close(resolve));
  });

  const url = `http://127.0.0.1:${server.address().port}/login`;
  for (let attempt = 0; attempt < 4; attempt += 1) {
    assert.equal((await fetch(url, { method: 'POST' })).status, 401);
  }

  const fifthAttempt = await fetch(url, { method: 'POST' });
  const body = await fifthAttempt.json();
  assert.equal(fifthAttempt.status, 429);
  assert.equal(body.retryAfterSeconds, 300);
  assert.equal(fifthAttempt.headers.get('retry-after'), '300');

  currentTime += 299_000;
  assert.equal((await fetch(url, { method: 'POST' })).status, 429);
  currentTime += 1_000;
  assert.equal((await fetch(url, { method: 'POST' })).status, 401);
});

test('successful login clears the failed-attempt count for the client IP', async t => {
  const lockout = createLoginLockout({ maxAttempts: 2, windowMs: 300_000 });
  const app = express();
  app.use('/login', lockout.middleware);
  app.post('/login/:result', (req, res) => {
    if (req.params.result === 'success') {
      lockout.recordSuccess(req);
      return res.json({ success: true });
    }
    const response = lockout.recordFailure(req, res);
    return response || res.status(401).json({ success: false });
  });
  const server = createServer(app);

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    lockout.close();
    return new Promise(resolve => server.close(resolve));
  });

  const baseUrl = `http://127.0.0.1:${server.address().port}/login`;
  assert.equal((await fetch(`${baseUrl}/failure`, { method: 'POST' })).status, 401);
  assert.equal((await fetch(`${baseUrl}/success`, { method: 'POST' })).status, 200);
  assert.equal((await fetch(`${baseUrl}/failure`, { method: 'POST' })).status, 401);
  assert.equal((await fetch(`${baseUrl}/failure`, { method: 'POST' })).status, 429);
});
