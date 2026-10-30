// A small HTML parser for the importer tests. Browsers use DOMParser; Node has none, and the
// converters only need nodeType, localName, childNodes, nodeValue and getAttribute. It handles
// well-formed export HTML plus the usual implied end tags, not the whole HTML5 algorithm.

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);
const RAW = new Set(['script', 'style', 'textarea', 'title']);
const CLOSES_P = new Set(['address', 'article', 'aside', 'blockquote', 'details', 'div', 'dl', 'fieldset', 'figure', 'footer', 'form',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'ul']);
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', hellip: '…', mdash: '—', ndash: '–', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', copy: '©' };

const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
  if (e[0] === '#') return String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
  return ENTITIES[e.toLowerCase()] ?? m;
});

class Node {
  constructor(nodeType) {
    this.nodeType = nodeType;
    this.childNodes = [];
    this.parentNode = null;
  }
  append(n) {
    n.parentNode = this;
    this.childNodes.push(n);
  }
}

class Element extends Node {
  constructor(name, attrs) {
    super(1);
    this.localName = name;
    this.nodeName = name.toUpperCase();
    this.attrs = attrs;
  }
  getAttribute(n) {
    return this.attrs.has(n) ? this.attrs.get(n) : null;
  }
}

class Text extends Node {
  constructor(v) {
    super(3);
    this.nodeValue = v;
  }
}

export function parseHtml(html) {
  const doc = new Node(9);
  const stack = [doc];
  const top = () => stack[stack.length - 1];
  const open = (name) => stack.some((n) => n.localName === name);
  const closeTo = (name) => {
    for (let i = stack.length - 1; i > 0; i--) {
      if (stack[i].localName === name) {
        stack.length = i;
        return;
      }
    }
  };
  let i = 0;
  while (i < html.length) {
    if (html.startsWith('<!--', i)) {
      const end = html.indexOf('-->', i + 4);
      i = end < 0 ? html.length : end + 3;
    } else if (html.startsWith('<!', i) || html.startsWith('<?', i)) {
      const end = html.indexOf('>', i);
      i = end < 0 ? html.length : end + 1;
    } else if (html.startsWith('</', i)) {
      const m = /^<\/([a-zA-Z][\w:-]*)\s*>/.exec(html.slice(i));
      if (!m) {
        top().append(new Text('<'));
        i++;
        continue;
      }
      const name = m[1].toLowerCase();
      if (open(name)) closeTo(name);
      i += m[0].length;
    } else if (html[i] === '<' && /[a-zA-Z]/.test(html[i + 1] || '')) {
      const m = /^<([a-zA-Z][\w:-]*)((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?)*)\s*(\/?)>/.exec(html.slice(i));
      if (!m) {
        top().append(new Text('<'));
        i++;
        continue;
      }
      const name = m[1].toLowerCase();
      const attrs = new Map();
      for (const a of m[2].matchAll(/([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
        attrs.set(a[1].toLowerCase(), decode(a[2] ?? a[3] ?? a[4] ?? ''));
      }
      if (CLOSES_P.has(name) && open('p')) closeTo('p');
      if (name === 'li' && top().localName === 'li') closeTo('li');
      if ((name === 'td' || name === 'th') && (top().localName === 'td' || top().localName === 'th')) stack.pop();
      if (name === 'tr' && open('tr')) closeTo('tr');
      if ((name === 'dt' || name === 'dd') && (top().localName === 'dt' || top().localName === 'dd')) stack.pop();
      const el = new Element(name, attrs);
      top().append(el);
      i += m[0].length;
      if (RAW.has(name)) {
        const end = html.toLowerCase().indexOf(`</${name}`, i);
        const stop = end < 0 ? html.length : end;
        el.append(new Text(name === 'title' || name === 'textarea' ? decode(html.slice(i, stop)) : html.slice(i, stop)));
        const close = html.indexOf('>', stop);
        i = end < 0 ? html.length : close + 1;
      } else if (!VOID.has(name) && !m[3]) {
        stack.push(el);
      }
    } else {
      const next = html.indexOf('<', i + 1);
      const end = next < 0 ? html.length : next;
      top().append(new Text(decode(html.slice(i, end))));
      i = end;
    }
  }
  return doc;
}
