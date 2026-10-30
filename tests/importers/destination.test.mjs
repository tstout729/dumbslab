import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveDestination } from '../../web/importers/destination.js';

const topics = [
  { id: 'rd-private', name: 'R&D / Strategy', visibility: 'private', parent_id: null },
  { id: 'rd-public', name: 'R&D - Strategy', visibility: 'org', parent_id: null },
  { id: 'eng', name: 'Engineering', visibility: 'org', parent_id: null },
  { id: 'nested', name: 'Ops', visibility: 'private', parent_id: 'eng' },
];

test('an existing topic is the destination by id, never renamed away from', () => {
  // The private topic's own name has a slash; the import must not slip into the public "R&D - Strategy".
  assert.deepEqual(resolveDestination('R&D / Strategy', topics), { id: 'rd-private', name: 'R&D / Strategy', exists: true, private: true, renamed: false });
  assert.equal(resolveDestination('  r&d   /  strategy ', topics).id, 'rd-private');
  // "R&D/Strategy" is the private topic as typed and the public one as the import would name it:
  // the private topic wins, in any order.
  assert.equal(resolveDestination('R&D/Strategy', topics).id, 'rd-private');
  assert.equal(resolveDestination('R&D/Strategy', [...topics].reverse()).id, 'rd-private');
  // Typing the public topic's name is a choice of that topic.
  assert.equal(resolveDestination('R&D - Strategy', topics).id, 'rd-public');
  assert.deepEqual(resolveDestination('engineering', topics), { id: 'eng', name: 'Engineering', exists: true, private: false, renamed: false });
});

test('a new destination gets the name the import will create, and says if it changed', () => {
  assert.deepEqual(resolveDestination('Ops / Runbooks', topics), { id: null, name: 'Ops - Runbooks', exists: false, private: false, renamed: true });
  // Only top-level topics are destinations by name.
  assert.equal(resolveDestination('Ops', topics).id, null);
  assert.deepEqual(resolveDestination('   ', topics), { id: null, name: '', exists: false, private: false, renamed: false });
});
