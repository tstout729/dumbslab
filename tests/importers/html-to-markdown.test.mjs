import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseHtml } from './mini-dom.mjs';
import { htmlToMarkdown, escapeText } from '../../web/importers/html-to-markdown.js';

const md = (html, hooks) => htmlToMarkdown(parseHtml(html), hooks);

test('text is escaped so it stays text', () => {
  assert.equal(md('<p>*not bold* 1 &lt; 2 [x](y) a|b `c` snake_case _x_</p>'), '\\*not bold\\* 1 \\< 2 \\[x\\](y) a\\|b \\`c\\` snake_case \\_x\\_');
  assert.equal(md('<p># not a heading</p><p>1. not a list</p><p>- nor this</p><p>&gt; nor a quote</p>'), '\\# not a heading\n\n1\\. not a list\n\n\\- nor this\n\n\\> nor a quote');
  assert.equal(escapeText('&amp; stays & entity-free'), '&amp;amp; stays & entity-free');
});

test('scripts, styles, handlers and unsafe links never come through', () => {
  const out = md('<p onclick="x()">Hi <a href="javascript:alert(1)">there</a></p><script>alert(1)</script><style>p{}</style><iframe src="javascript:x"></iframe><form><input value="v"><button>Go</button></form><p hidden>secret</p>');
  assert.equal(out, 'Hi there');
});

test('inline formatting, links and images', () => {
  assert.equal(md('<p><b> bold </b><i>it</i><s>gone</s><code>a`b</code><sup>2</sup><br>next</p>'), ' **bold** *it*~~gone~~``a`b``<sup>2</sup>\\\nnext'.trim());
  assert.equal(md('<p><a href="https://e.com/a b(c)">see <b>this</b></a> <img src="https://e.com/i.png" alt="pic"> <img src="local.png"></p>'), '[see **this**](https://e.com/a%20b%28c%29) ![pic](https://e.com/i.png)');
  const hooks = { link: (href) => (href === 'p.html' ? { url: 'dsimport:page:1' } : null), image: () => ({ text: '*gone*' }) };
  assert.equal(md('<p><a href="p.html">Page</a> <a href="q.html">Other</a> <img src="x.png"></p>', hooks), '[Page](dsimport:page:1) Other *gone*');
});

test('headings, lists, tasks and code', () => {
  assert.equal(md('<h2>Set <em>up</em></h2><ul><li>One<ul><li>Nested</li></ul></li><li>Two</li></ul>'), '## Set *up*\n\n- One\n  - Nested\n- Two');
  assert.equal(md('<ol start="3"><li><p>Para</p><p>More</p></li><li>Next</li></ol>'), '3. Para\n\n   More\n\n4. Next');
  assert.equal(md('<ul class="inline-task-list"><li class="checked">Done</li><li>Todo</li></ul><ul><li><input type="checkbox" checked> Box</li></ul>'), '- [x] Done\n- [ ] Todo\n\n- [x] Box');
  assert.equal(md('<pre class="syntaxhighlighter-pre" data-syntaxhighlighter-params="brush: sql; gutter: false">SELECT 1;\n```\nx</pre>'), '````sql\nSELECT 1;\n```\nx\n````');
  assert.equal(md('<pre data-ghq-code-block-prism="bash"><code>one</code><code>two</code></pre>'), '```bash\none\ntwo\n```');
  assert.equal(md('<pre><code class="language-js">let a = 1;</code></pre>'), '```js\nlet a = 1;\n```');
});

test('Confluence macros become callouts, toggles and quotes', () => {
  const kinds = ['information', 'tip', 'note', 'warning'].map((k) => md(`<div class="confluence-information-macro confluence-information-macro-${k}"><span class="aui-icon confluence-information-macro-icon"></span><div class="confluence-information-macro-body"><p>Body</p></div></div>`));
  assert.deepEqual(kinds, ['> [!NOTE]\n> Body', '> [!TIP]\n> Body', '> [!WARNING]\n> Body', '> [!CAUTION]\n> Body']);
  assert.equal(md('<div class="confluence-information-macro confluence-information-macro-tip"><p class="title">Hint</p><div class="confluence-information-macro-body"><p>A</p><p>B</p></div></div>'), '> [!TIP]\n> **Hint**\n>\n> A\n>\n> B');
  assert.equal(md('<div data-panel-type="success"><p>Yes</p></div>'), '> [!TIP]\n> Yes');
  assert.equal(md('<div class="expand-container"><div class="expand-control"><span class="expand-control-text">More &lt;info&gt;</span></div><div class="expand-content"><p>Hidden</p></div></div>'), '<details>\n<summary>More &lt;info&gt;</summary>\n\nHidden\n\n</details>');
  assert.equal(md('<div class="panel"><div class="panelHeader">Box</div><div class="panelContent"><p>Inside</p></div></div>'), '> **Box**\n>\n> Inside');
  assert.equal(md('<p><span class="status-macro aui-lozenge">DONE</span> <img class="emoticon emoticon-tick" data-emoji-fallback="✅" src="x.svg"> <a class="confluence-userlink user-mention" href="https://x/people/1">Ada</a></p>'), '`DONE` ✅ Ada');
  assert.equal(md('<div class="toc-macro"><ul><li>Contents</li></ul></div><p>Text</p>'), 'Text');
});

test('tables keep their shape', () => {
  const out = md('<table><thead><tr><th>A</th><th>B</th><th>C</th></tr></thead><tbody><tr><td rowspan="2">tall</td><td colspan="2">wide | piped</td></tr><tr><td><p>x</p><p>y</p></td><td><ul><li>i</li><li>j</li></ul></td></tr></tbody></table>');
  assert.equal(out, '| A | B | C |\n| --- | --- | --- |\n| tall | wide \\| piped |  |\n|  | x<br>y | - i<br>- j |');
});

test('frames become links on their own line, which posts embed', () => {
  assert.equal(md('<p>Watch:<iframe src="https://www.youtube.com/embed/abc"></iframe></p>'), 'Watch:\n\n<https://www.youtube.com/embed/abc>');
});

test('spans and nesting can’t blow a page up', () => {
  // 100 cells spanning 50 columns each, then 500 rows: padding every row would be megabytes.
  const probe = '<table><tr>' + '<td colspan="50">a</td>'.repeat(100) + '</tr>' + '<tr><td>b</td></tr>'.repeat(500) + '</table>';
  const out = md(probe);
  assert.ok(probe.length > 10_000 && out.length < probe.length, `${probe.length} → ${out.length}`);
  assert.ok(out.startsWith('- a · a · a') && out.endsWith('- b'), out.slice(0, 40));
  const tall = '<table><tr><td rowspan="500" colspan="50">a</td><td>x</td></tr>' + '<tr><td>b</td></tr>'.repeat(900) + '</table>';
  assert.ok(md(tall).length < tall.length);
  // Ordinary spans still make a table.
  assert.equal(md('<table><tr><th colspan="2">Both</th></tr><tr><td>x</td><td>y</td></tr></table>'), '| Both |  |\n| --- | --- |\n| x | y |');
  // Nesting past twelve levels reads as text instead of multiplying indentation and quote marks.
  const lists = md('<ul><li>x'.repeat(800) + '</li></ul>'.repeat(800));
  assert.ok(lists.length < 3000, String(lists.length));
  const quotes = md('<blockquote><p>q</p>'.repeat(600) + '</blockquote>'.repeat(600));
  assert.ok(quotes.length < 40_000, String(quotes.length));
});
