// Each format's fixture zip, converted end to end (zip reader, source, converter, plan).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureZip } from './helpers.mjs';
import { parseHtml } from './mini-dom.mjs';
import { zipSource } from '../../web/importers/source.js';
import { detectFormat, convert } from '../../web/importers/index.js';

async function load(name, opts = {}) {
  const src = await zipSource(await fixtureZip(name, opts), `${name}.zip`);
  const format = detectFormat(src);
  const plan = await convert(format, src, { parseHtml, ...(opts.convert || {}) });
  const doc = (title) => plan.documents.find((d) => d.title === title);
  const token = (title) => `dsimport:page:${doc(title).n}`;
  return { src, format, plan, doc, token };
}

const outline = (plan) => plan.documents.map((d) => [d.title, d.topic.join('/')]);

test('Confluence: the page tree becomes topics under the space', async () => {
  const { format, plan, doc, token } = await load('confluence');
  assert.equal(format, 'confluence');
  assert.equal(plan.rootTopic, 'Engineering Handbook');
  assert.deepEqual(outline(plan), [
    ['Engineering Handbook', ''],
    ['Onboarding', 'Onboarding'],
    ['Laptop setup', 'Onboarding'],
    ['Runbooks / On-call', 'Runbooks - On-call'],
    ['Deploy the API', 'Runbooks - On-call'],
    ['Deploy the API (2)', 'Runbooks - On-call'],
    ['FAQ', ''],
  ]);
  // Links between pages, by file name, wiki URL or site path; missing pages and scripts drop out.
  assert.match(doc('Engineering Handbook').markdown, new RegExp(`\\[Onboarding\\]\\(${token('Onboarding')}\\)`));
  const runbooks = doc('Runbooks / On-call').markdown;
  assert.ok(runbooks.includes(`[Deploy the API](${token('Deploy the API')})`), runbooks);
  assert.ok(runbooks.includes(`[FAQ](${token('FAQ')})`), runbooks);
  assert.ok(runbooks.startsWith('> [!CAUTION]\n> **Paging**'), runbooks);
  assert.ok(!/alert|script|createpage|javascript/.test(plan.documents.map((d) => d.markdown).join('\n')));
  const onboarding = doc('Onboarding').markdown;
  assert.ok(onboarding.includes('- [x] Read the [laptop setup]('), onboarding);
  assert.ok(onboarding.includes('Missing page: Later. Bad link: click.'), onboarding);
  // Attachments get their real names; icons aren't uploaded; listed-only files join an Attachments list.
  assert.deepEqual(plan.attachments.map((a) => [a.path, a.name]), [
    ['attachments/1003/2002', 'checklist.pdf'],
    ['attachments/1003/2001.png', 'dock.png'],
    ['attachments/1005/2003.txt', 'rollback-notes.txt'],
  ]);
  const laptop = doc('Laptop setup').markdown;
  assert.ok(laptop.includes('![Dock diagram](dsimport:file:1)'), laptop);
  assert.ok(laptop.includes('```bash\nbrew install git'), laptop);
  assert.ok(!laptop.includes('## Attachments'), 'files the page already shows aren’t listed again');
  assert.ok(doc('Deploy the API').markdown.endsWith('## Attachments\n\n- [rollback-notes.txt](dsimport:file:2)'));
  assert.ok(doc('FAQ').markdown.endsWith('<https://www.youtube.com/embed/9pasx0ghADM>'));

  const { plan: lean } = await load('confluence', { convert: { attachmentLists: false } });
  assert.equal(lean.attachments.length, 2);
});

test('Guru: folders and sections become topics, cards posts', async () => {
  const { format, plan, doc, token } = await load('guru', { prefix: 'export-20261030-/' });
  assert.equal(format, 'guru');
  assert.equal(plan.rootTopic, 'Support Playbook');
  assert.deepEqual(outline(plan), [
    ['Sending an invoice', 'Billing'],
    ['Issuing a refund', 'Billing/Refunds'],
    ['Handling a chargeback', 'Billing/Disputes'],
    ['Welcome to support', ''],
  ]);
  const invoice = doc('Sending an invoice').markdown;
  assert.ok(invoice.includes(`[Refunds](${token('Issuing a refund')})`), invoice);
  assert.ok(invoice.includes('[attached](dsimport:file:0)') && invoice.includes('![Logo](dsimport:file:1)'), invoice);
  assert.ok(!/hidden tracking|track\(\)/.test(invoice), invoice);
  assert.ok(doc('Issuing a refund').markdown.includes(`[chargebacks](${token('Handling a chargeback')})`));
  const chargeback = doc('Handling a chargeback').markdown;
  assert.ok(chargeback.includes('```bash\ndispute fetch --id 9\ndispute answer --id 9\n```'), chargeback);
  assert.ok(chargeback.includes('> [!WARNING]\n> Never refund a disputed charge.'), chargeback);
  assert.deepEqual(plan.attachments.map((a) => a.path), ['resources/refund-policy.pdf', 'resources/logo.png']);
});

test('GitHub wiki: the sidebar arranges pages; wiki links resolve; specials are skipped', async () => {
  const config = '[remote "origin"]\n\turl = https://github.com/acme/widgets.wiki.git\n';
  const { format, plan, doc, token } = await load('github-wiki', { extra: { 'widgets.wiki/.git/config': config } });
  assert.equal(format, 'github-wiki');
  assert.equal(plan.rootTopic, 'widgets wiki');
  assert.deepEqual(outline(plan), [
    ['Home', ''],
    ['Getting Started', 'Guides'],
    ['Deploy Guide', 'Guides/Deploy Guide'],
    ['Advanced Topics', 'Guides/Deploy Guide'],
  ]);
  const home = doc('Home').markdown;
  // [[Text|Page]]: GitHub reads the text first.
  assert.ok(home.includes(`[Getting Started](${token('Getting Started')})`), home);
  assert.ok(home.includes(`[the deploy guide](${token('Deploy Guide')})`), home);
  assert.ok(home.includes(`[Advanced topics](${token('Advanced Topics')})`), home);
  assert.ok(home.includes('![Architecture](dsimport:file:0)') && home.includes('![Architecture again](dsimport:file:0)'), home);
  const started = doc('Getting Started').markdown;
  assert.ok(started.includes('```md\n[[Not A Link]] and [x](Home)\n```'), 'code stays as written');
  assert.ok(started.includes('<img src="dsimport:file:0" width="200">') && !/onerror|<script/.test(started), started);
  assert.ok(started.includes(`Back [home](${token('Home')})`), 'the wiki’s own URL points at the imported page');
  assert.ok(doc('Deploy Guide').markdown.includes('and Missing Page later'));
  assert.deepEqual(plan.skipped.map((s) => s.path).sort(), ['Old-Notes.textile', '_Footer.md', '_Sidebar.md']);
});

test('Markdown folder: folders are topics, titles come from front matter or headings', async () => {
  const { format, plan, doc, token } = await load('markdown');
  assert.equal(format, 'markdown');
  assert.equal(plan.rootTopic, 'docs');
  assert.deepEqual(outline(plan), [
    ['Widgets documentation', ''],
    ['Getting started', ''],
    ['guides', 'guides'],
    ['Configuring widgets', 'guides'],
    ['Install', 'guides'],
  ]);
  const readme = doc('Widgets documentation').markdown;
  assert.ok(readme.includes(`[guides](${token('guides')})`) && readme.includes('See the changelog too.'), readme);
  assert.ok(doc('Getting started').markdown.includes(`[configure it](${token('Configuring widgets')}#options)`));
  assert.ok(doc('Getting started').markdown.includes('<a href="#">bad link</a>'));
  assert.ok(doc('Install').markdown.includes('![Diagram](dsimport:file:0 "The diagram")'));
  assert.ok(doc('Install').markdown.includes(`[start]: ${token('Widgets documentation')}`));
  assert.ok(doc('Configuring widgets').markdown.includes('A missing image: *gone*'));
  assert.deepEqual(plan.skipped.map((s) => s.path), ['component.mdx']);
});

test('large attachments are skipped and listed', async () => {
  const big = new Uint8Array(10 * 1024 * 1024 + 1);
  big.set([0x89, 0x50, 0x4e, 0x47]);
  const { plan } = await load('markdown', { extra: { 'docs/img/diagram.png': big } });
  assert.equal(plan.attachments.length, 0);
  assert.match(plan.skipped.find((s) => s.path === 'img/diagram.png').reason, /10 MB/);
  assert.ok(plan.documents.find((d) => d.title === 'Install').markdown.includes('*Diagram*'));
});
