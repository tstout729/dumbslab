import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rewriteMarkdown, splitFrontMatter, leadingTitle } from '../../web/importers/markdown.js';
import { parseYaml } from '../../web/importers/yaml.js';
import { fillTokens, pendingLink } from '../../web/importers/plan.js';
import { localTarget } from '../../web/importers/paths.js';

test('links, images, wiki links and definitions are rewritten outside code', () => {
  const seen = [];
  const out = rewriteMarkdown(
    'See [a](a.md "t") and ![i](img/i.png) and [![badge](b.png)](b.md).\n\n`[c](c.md)` and [[Wiki Page]]\n\n```\n[d](d.md) [[Not]]\n```\n\n[ref]: r.md\n<img src="h.png"> <a href=\'x.md\'>x</a>',
    {
      link: (t, { image }) => {
        seen.push([t, image]);
        return `T(${t})`;
      },
      wikiLink: (inner) => `W(${inner})`,
    },
  );
  assert.equal(out, 'See [a](T(a.md) "t") and ![i](T(img/i.png)) and [![badge](T(b.png))](T(b.md)).\n\n`[c](c.md)` and W(Wiki Page)\n\n```\n[d](d.md) [[Not]]\n```\n\n[ref]: T(r.md)\n<img src="T(h.png)"> <a href="T(x.md)">x</a>');
  assert.deepEqual(seen.filter(([, image]) => image).map(([t]) => t), ['img/i.png', 'b.png', 'h.png']);
});

test('active HTML in Markdown is removed, code examples are not', () => {
  const out = rewriteMarkdown('<script>alert(1)</script>\n<img src="a.png" onerror="alert(2)"> <a href="javascript:x()">y</a>\n\n```html\n<script>shown()</script>\n```', {});
  assert.equal(out, '\n<img src="a.png"> <a href="#">y</a>\n\n```html\n<script>shown()</script>\n```');
});

test('front matter and leading titles', () => {
  assert.deepEqual(splitFrontMatter('---\ntitle: "Hi: there"\nweight: 2\n---\nBody'), { data: { title: 'Hi: there', weight: '2' }, body: 'Body' });
  assert.deepEqual(leadingTitle('# Hello *world*\n\nText'), { title: 'Hello world', body: 'Text' });
  assert.deepEqual(leadingTitle('Install\n=======\n\nText'), { title: 'Install', body: 'Text' });
  assert.equal(leadingTitle('Just text'), null);
});

test('Guru metadata YAML', () => {
  const y = parseYaml('Title: "Billing"\nDescription: |\n  Two\n  lines\nItems:\n- ID: "c1"\n  Type: "card"\n- Type: section\n  Title: Refunds # a comment\n  Items:\n    - ID: c2\n      Type: card\nTags: [a, "b"]\nVersion: 2\nEmpty:\n');
  assert.deepEqual(y, {
    Title: 'Billing',
    Description: 'Two\nlines',
    Items: [{ ID: 'c1', Type: 'card' }, { Type: 'section', Title: 'Refunds', Items: [{ ID: 'c2', Type: 'card' }] }],
    Tags: ['a', 'b'],
    Version: 2,
    Empty: null,
  });
});

test('tokens fill in, and links to what is gone keep their text', () => {
  const md = '[A](dsimport:page:0) [B](dsimport:page:1#x) ![C](dsimport:file:0) ![](dsimport:file:1) [D](dsimport:file:1)\n[r]: dsimport:page:1';
  const out = fillTokens(md, { page: (n) => (n === 0 ? '/p/abc' : null), file: (n) => (n === 0 ? '/files/f1/c.png' : null) });
  assert.equal(out, '[A](/p/abc) B ![C](/files/f1/c.png)  D\n[r]: #');
  assert.match(pendingLink({ title: 'Deploy (v2)', key: 'a.html' }), /^\/search\?q=Deploy%20%28v2%29&import=[0-9a-f]{8}$/);
});

test('a + in a link path is itself, not a space', () => {
  assert.deepEqual(localTarget('C++.md'), { path: 'C++.md', query: '' });
  assert.deepEqual(localTarget('images/a+b.png?raw=1'), { path: 'images/a+b.png', query: '?raw=1' });
  assert.deepEqual(localTarget('My%20Page.md#top'), { path: 'My Page.md', query: '#top' });
});
