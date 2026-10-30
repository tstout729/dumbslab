// The sign-up site on the root domain: reserve an address, then continue to the new workspace's
// own setup page with a one-hour sign-up link. While someone types an address, the page's
// examples (the demo's URL bar, the MCP command) show it.

const rootHost = location.host; // includes a port in local development
for (const el of document.querySelectorAll('[data-root]')) el.textContent = rootHost;
for (const el of document.querySelectorAll('[data-scheme]')) el.textContent = `${location.protocol}//`;

const SLUG = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){1,30}[a-z0-9]$/;
const EXAMPLE = 'acme';
const FORMAT_HINT = 'Use 3 to 32 lowercase letters, numbers and single hyphens.';

// "Acme Docs" becomes acme-docs. A trailing hyphen stays while typing, so acme- can become acme-docs.
function toAddress(text) {
  return text
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[\s_.]+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-{2,}/g, '-')
    .replace(/^-+/, '')
    .slice(0, 32);
}

// The setup page asks for the real name; this is its starting value. acme-docs becomes Acme Docs.
function nameFor(address) {
  return address.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ');
}

// Server messages start lowercase and quote addresses in backticks.
function sentence(message, address) {
  const text = message.replace(/`/g, '');
  return !text || text.startsWith(address) ? text : text[0].toUpperCase() + text.slice(1);
}

// ---------------------------------------------------------------------------
// Sign-up

const form = document.getElementById('signup');
const addressInput = document.getElementById('ws-address');
const status = document.getElementById('ws-address-status');
const errorBox = document.getElementById('signup-error');
const submit = form.querySelector('button[type=submit]');
const startHint = status.textContent;
const addressSpots = document.querySelectorAll('[data-address]');

// The input is only as wide as its text, so the suffix reads as part of one URL.
const measure = document.createElement('span');
measure.className = 'w-measure';
measure.setAttribute('aria-hidden', 'true');
addressInput.after(measure);
function fit() {
  measure.textContent = addressInput.value || addressInput.placeholder;
  measure.classList.toggle('is-placeholder', !addressInput.value);
  // Plus the input's 1px side padding.
  addressInput.style.width = `${Math.ceil(measure.getBoundingClientRect().width) + 2}px`;
}
addressInput.closest('.w-url').addEventListener('click', () => addressInput.focus());

function setStatus(state, text) {
  status.dataset.state = state;
  status.textContent = text;
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

let checkTimer = 0;
let checkSeq = 0;

function addressChanged() {
  const address = addressInput.value;
  const valid = SLUG.test(address);
  for (const el of addressSpots) el.textContent = valid ? address : EXAMPLE;
  fit();
  errorBox.hidden = true;
  clearTimeout(checkTimer);
  const seq = ++checkSeq;
  if (!address) return setStatus('', startHint);
  if (!valid) return setStatus('', FORMAT_HINT);
  setStatus('busy', `Checking ${address}.${rootHost}…`);
  // Only a hint: /api/signup has the final say.
  checkTimer = setTimeout(async () => {
    try {
      const res = await fetch(`/api/signup/check?address=${encodeURIComponent(address)}`);
      const body = await res.json();
      if (seq !== checkSeq) return;
      if (!res.ok) throw new Error(body.error?.message);
      if (body.available) setStatus('ok', `${address}.${rootHost} is available`);
      else setStatus('taken', sentence(body.message || `${address} is taken`, address));
    } catch {
      if (seq === checkSeq) setStatus('', startHint);
    }
  }, 250);
}

// Rewrites what someone typed into an address as they type, keeping the caret in place.
function cleanAddressInput(input) {
  const raw = input.value;
  const clean = toAddress(raw);
  if (clean === raw) return;
  const atEnd = input.selectionStart === raw.length;
  const caret = atEnd ? clean.length : Math.min(input.selectionStart, clean.length);
  input.value = clean;
  input.setSelectionRange(caret, caret);
}

addressInput.addEventListener('input', () => {
  cleanAddressInput(addressInput);
  addressChanged();
});
addressInput.addEventListener('change', () => {
  const trimmed = addressInput.value.replace(/-+$/, '');
  if (trimmed !== addressInput.value) {
    addressInput.value = trimmed;
    addressChanged();
  }
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.hidden = true;
  const address = addressInput.value.replace(/-+$/, '');
  if (!SLUG.test(address)) {
    showError(address ? 'The address must be 3 to 32 lowercase letters, numbers or single hyphens.' : 'Type an address for your workspace.');
    addressInput.focus();
    return;
  }
  const label = submit.textContent;
  submit.disabled = true;
  submit.setAttribute('aria-busy', 'true');
  submit.textContent = 'Creating…';
  try {
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-dumbslab-client': 'web' },
      body: JSON.stringify({ workspace_name: nameFor(address), address }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(sentence(body.error?.message || 'something went wrong; please try again', address));
    location.href = body.setup_url;
  } catch (err) {
    showError(err instanceof TypeError ? 'Couldn’t reach DumbSlab. Check your connection and try again.' : err.message);
    submit.disabled = false;
    submit.removeAttribute('aria-busy');
    submit.textContent = label;
  }
});

fit();

// Buttons further down the page bring people back to the address field.
for (const link of document.querySelectorAll('[data-focus-signup]')) {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
    form.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'center' });
    addressInput.focus({ preventScroll: true });
  });
}

// ---------------------------------------------------------------------------
// Copy buttons

for (const btn of document.querySelectorAll('.w-copy-btn')) {
  const label = btn.getAttribute('aria-label');
  btn.addEventListener('click', async () => {
    const source = btn.parentElement.querySelector('[data-copy-source]');
    try {
      await navigator.clipboard.writeText(source.textContent);
      btn.textContent = 'Copied';
    } catch {
      getSelection().selectAllChildren(source);
      btn.textContent = 'Press ⌘C';
    }
    btn.setAttribute('aria-label', btn.textContent);
    setTimeout(() => {
      btn.textContent = 'Copy';
      btn.setAttribute('aria-label', label);
    }, 1800);
  });
}

// ---------------------------------------------------------------------------
// Sign in to an existing workspace

const signin = document.querySelector('.w-signin');
const gotoInput = document.getElementById('goto-address');
signin.addEventListener('toggle', () => {
  if (signin.open) gotoInput.focus();
});
document.addEventListener('click', (e) => {
  if (signin.open && !signin.contains(e.target)) signin.open = false;
});
signin.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && signin.open) {
    signin.open = false;
    signin.querySelector('summary').focus();
  }
});
document.getElementById('goto').addEventListener('submit', (e) => {
  e.preventDefault();
  const address = gotoInput.value.replace(/-+$/, '');
  if (!SLUG.test(address)) {
    gotoInput.setAttribute('aria-invalid', 'true');
    gotoInput.focus();
    return;
  }
  location.href = `${location.protocol}//${address}.${rootHost}/login`;
});
gotoInput.addEventListener('input', () => {
  cleanAddressInput(gotoInput);
  gotoInput.removeAttribute('aria-invalid');
});

// Pricing shows the server's own limits.
function size(bytes) {
  const gb = bytes / (1024 * 1024 * 1024);
  return gb >= 1 ? `${Number.isInteger(gb) ? gb : gb.toFixed(1)} GB` : `${Math.round(bytes / (1024 * 1024))} MB`;
}
const fill = (attr, text) => { for (const el of document.querySelectorAll(`[${attr}]`)) el.textContent = text; };
fetch('/api/plans').then((r) => (r.ok ? r.json() : null)).then((p) => {
  if (!p) return;
  fill('data-free-storage', size(p.free.storage_bytes));
  fill('data-free-writes', p.free.writes_per_day.toLocaleString('en-US'));
  fill('data-pro-storage', size(p.pro.allowance.storage_bytes));
  fill('data-pro-writes', p.pro.allowance.writes_per_day.toLocaleString('en-US'));
  fill('data-pro-price', p.pro.price);
  document.querySelector('[data-pro-soon]').hidden = p.pro.available;
}).catch(() => {});
