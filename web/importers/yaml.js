// A small YAML reader for export metadata (Guru's collection, folder and card files): block
// mappings and sequences, flow lists of scalars, quoted and plain scalars, and `|`/`>` block
// text. Anchors, tags and multi-document streams aren't needed and aren't supported.

export function parseYaml(text) {
  const lines = [];
  for (const raw of String(text).replace(/^﻿/, '').replace(/\r\n?/g, '\n').split('\n')) {
    if (/^\s*(#.*)?$/.test(raw) || /^(---|\.\.\.)\s*$/.test(raw)) {
      lines.push({ blank: true, raw });
      continue;
    }
    lines.push({ indent: raw.match(/^ */)[0].length, text: raw.trim(), raw });
  }
  let i = 0;
  const skipBlank = () => {
    while (i < lines.length && lines[i].blank) i++;
  };

  function block(indent) {
    skipBlank();
    if (i >= lines.length || lines[i].indent < indent) return null;
    return lines[i].text.startsWith('- ') || lines[i].text === '-' ? sequence(lines[i].indent) : mapping(lines[i].indent);
  }

  function sequence(indent) {
    const out = [];
    for (;;) {
      skipBlank();
      if (i >= lines.length || lines[i].indent !== indent || !(lines[i].text.startsWith('- ') || lines[i].text === '-')) break;
      const rest = lines[i].text.slice(1).trim();
      if (!rest) {
        i++;
        out.push(block(indent + 1));
      } else if (keyValue(rest)) {
        // "- key: value" starts a mapping whose keys line up after the dash.
        const inner = indent + (lines[i].text.length - rest.length);
        lines[i] = { indent: inner, text: rest, raw: lines[i].raw };
        out.push(mapping(inner));
      } else {
        i++;
        out.push(scalar(rest));
      }
    }
    return out;
  }

  function mapping(indent) {
    const out = {};
    for (;;) {
      skipBlank();
      if (i >= lines.length || lines[i].indent !== indent) break;
      const kv = keyValue(lines[i].text);
      if (!kv) break;
      i++;
      const [key, value] = kv;
      if (value === '|' || value === '>' || /^[|>][+-]?\d*$/.test(value)) {
        out[key] = blockScalar(indent, value[0] === '>');
      } else if (value === '') {
        skipBlank();
        const nested = i < lines.length && (lines[i].indent > indent || (lines[i].indent === indent && lines[i].text.startsWith('- ')));
        out[key] = nested ? block(lines[i].indent) : null;
      } else {
        out[key] = scalar(value);
      }
    }
    return out;
  }

  function blockScalar(indent, folded) {
    const body = [];
    let inner = null;
    while (i < lines.length) {
      const l = lines[i];
      const ind = l.blank ? Infinity : l.indent;
      if (!l.blank && ind <= indent) break;
      if (inner === null && !l.blank) inner = ind;
      body.push(l.blank ? '' : l.raw.slice(inner));
      i++;
    }
    while (body.length && body[body.length - 1] === '') body.pop();
    return folded ? body.join('\n').replace(/([^\n])\n(?=[^\n])/g, '$1 ') : body.join('\n');
  }

  return block(0);
}

function keyValue(text) {
  const m = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s:#][^:#]*?)\s*:(?:\s+(.*)|$)/.exec(text);
  if (!m) return null;
  return [String(scalar(m[1])), (m[2] || '').replace(/\s+#.*$/, '').trim()];
}

function scalar(v) {
  const s = v.trim();
  if (s.startsWith('"')) {
    const end = s.lastIndexOf('"');
    try {
      return JSON.parse(s.slice(0, end + 1));
    } catch {
      return s.slice(1, end);
    }
  }
  if (s.startsWith("'")) return s.slice(1, s.lastIndexOf("'")).replace(/''/g, "'");
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    return inner ? inner.split(',').map((x) => scalar(x)) : [];
  }
  const plain = s.replace(/\s+#.*$/, '');
  if (plain === 'null' || plain === '~') return null;
  if (plain === 'true') return true;
  if (plain === 'false') return false;
  if (/^-?\d+(\.\d+)?$/.test(plain)) return Number(plain);
  return plain;
}
