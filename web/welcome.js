// The sign-up site on the root domain: reserve an address, then continue to the new
// workspace's own setup page with a one-hour sign-up link.

const rootHost = location.host; // includes a port in local development
const rootName = location.hostname;
for (const el of document.querySelectorAll('[data-root]')) el.textContent = rootName;

const SLUG = /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){1,30}[a-z0-9]$/;

function slugify(text) {
  return text
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32)
    .replace(/-+$/, '');
}

const form = document.getElementById('signup');
const nameInput = document.getElementById('ws-name');
const addressInput = document.getElementById('ws-address');
const errorBox = document.getElementById('signup-error');
const submit = form.querySelector('button[type=submit]');
let addressEdited = false;

nameInput.addEventListener('input', () => {
  if (!addressEdited) addressInput.value = slugify(nameInput.value);
});
addressInput.addEventListener('input', () => {
  addressEdited = addressInput.value !== '';
  addressInput.value = addressInput.value.toLowerCase().replace(/[^a-z0-9-]/g, '');
});

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorBox.hidden = true;
  const workspaceName = nameInput.value.trim();
  const address = addressInput.value.trim();
  if (!workspaceName) return showError('Give your workspace a name.');
  if (!SLUG.test(address)) return showError('The address must be 3 to 32 lowercase letters, numbers or single hyphens.');
  submit.disabled = true;
  submit.setAttribute('aria-busy', 'true');
  try {
    const res = await fetch('/api/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-dumbslab-client': 'web' },
      body: JSON.stringify({ workspace_name: workspaceName, address }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error?.message || 'Something went wrong. Please try again.');
    location.href = body.setup_url;
  } catch (err) {
    showError(err.message);
    submit.disabled = false;
    submit.removeAttribute('aria-busy');
  }
});

document.getElementById('goto').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = document.getElementById('goto-address');
  const address = input.value.trim().toLowerCase();
  if (!SLUG.test(address)) {
    input.focus();
    return;
  }
  location.href = `${location.protocol}//${address}.${rootHost}/login`;
});
