// Where an import goes. The preview and the run use the same answer, so what the preview says
// about who will see the import is what happens.

import { topicSegment } from './paths.js';

/**
 * Resolves the top topic someone typed against the top-level topics they can see.
 * - An existing topic whose name matches what was typed (ignoring case and spacing), or
 *   the name the import would give a new topic, is used by id. When several match, a private
 *   one wins, so the import never lands somewhere more people can see than intended.
 * - Otherwise the import creates a topic. Slashes separate topics, so they become hyphens;
 *   `renamed` says when that changed the name.
 * - Empty means no top topic: pages go into top-level topics.
 * Returns { id, name, exists, private, renamed }.
 */
export function resolveDestination(typed, topics) {
  const raw = String(typed || '').replace(/\s+/g, ' ').trim();
  if (!raw) return { id: null, name: '', exists: false, private: false, renamed: false };
  const name = topicSegment(raw);
  // Spacing and case don't tell topics apart here ("R&D/Strategy" is "R&D / Strategy").
  const norm = (s) => String(s || '').replace(/\s+/g, '').toLowerCase();
  const matches = (topics || []).filter((t) => !t.parent_id && (norm(t.name) === norm(raw) || norm(t.name) === norm(name)));
  matches.sort((a, b) => Number(b.visibility === 'private') - Number(a.visibility === 'private'));
  const found = matches[0];
  if (found) return { id: found.id, name: found.name, exists: true, private: found.visibility === 'private', renamed: false };
  return { id: null, name, exists: false, private: false, renamed: name !== raw };
}
