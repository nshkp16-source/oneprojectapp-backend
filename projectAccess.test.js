import test from 'node:test';
import assert from 'node:assert/strict';
import { checkProjectAccess } from './projectAccess.js';

const identity = (role) => role;

test('project access checks require the caller assignment for that project', async () => {
  const pool = {
    query: async (sql, params) => {
      assert.match(sql, /contractor_pm_assignments/);
      assert.deepEqual(params, [42, 7]);
      return { rows: [{}] };
    },
  };

  assert.equal(await checkProjectAccess(pool, 7, 'ContractorPM', 42, identity), true);
});

test('project access denies callers without a matching assignment', async () => {
  const pool = {
    query: async (_sql, params) => {
      assert.deepEqual(params, [42, 7]);
      return { rows: [] };
    },
  };

  assert.equal(await checkProjectAccess(pool, 7, 'ContractorPM', 42, identity), false);
});

test('client project access checks project ownership', async () => {
  const pool = {
    query: async (sql, params) => {
      assert.match(sql, /FROM projects WHERE id=\$1 AND client_id=\$2/);
      assert.deepEqual(params, [42, 7]);
      return { rows: [{}] };
    },
  };

  assert.equal(await checkProjectAccess(pool, 7, 'Client', 42, identity), true);
});

test('project access denies unknown roles without querying the database', async () => {
  const pool = { query: async () => assert.fail('unknown roles must not query the database') };

  assert.equal(await checkProjectAccess(pool, 7, 'Unknown', 42, identity), false);
});
