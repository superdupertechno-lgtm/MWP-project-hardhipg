// End-to-end smoke test: `npm test`. Uses a throwaway database in a temp folder.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'handle-test-'));
process.env.AUTH_RATE_LIMIT = '1000';

const app = require('../server');

let server;
let base;
test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server.close());

/** Tiny cookie-keeping client. */
function client() {
  let cookie = '';
  async function request(method, url, { form, multipart } = {}) {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    let body;
    if (form) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(form).toString();
    } else if (multipart) {
      body = multipart;
    }
    const res = await fetch(base + url, { method, headers, body, redirect: 'manual' });
    const set = res.headers.getSetCookie();
    if (set.length) {
      const jar = Object.fromEntries(cookie.split('; ').filter(Boolean).map((c) => c.split('=')));
      for (const c of set) {
        const [pair] = c.split(';');
        const [k, ...rest] = pair.split('=');
        if (/Max-Age=0|Expires=Thu, 01 Jan 1970/i.test(c)) delete jar[k];
        else jar[k] = rest.join('=');
      }
      cookie = Object.entries(jar).map(([k, val]) => `${k}=${val}`).join('; ');
    }
    return { status: res.status, location: res.headers.get('location'), text: await res.text() };
  }
  async function token(url) {
    const { text } = await request('GET', url);
    const m = text.match(/name="_csrf" value="([^"]+)"/);
    assert.ok(m, `no csrf token on ${url}`);
    return m[1];
  }
  return { request, token };
}

// 1x1 transparent PNG
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64'
);

function multipartBody(fields, file) {
  const fd = new FormData();
  for (const [k, val] of Object.entries(fields)) fd.append(k, val);
  if (file) fd.append('avatar', new Blob([file.data], { type: file.type }), file.name);
  return fd;
}

const creds = { username: 'ada_l', email: 'ada@example.com', password: 'correct horse battery' };

test('home page renders', async () => {
  const c = client();
  const res = await c.request('GET', '/');
  assert.equal(res.status, 200);
  assert.match(res.text, /Your name,/);
});

test('signup rejects bad input and missing CSRF', async () => {
  const c = client();
  const t = await c.token('/signup');

  let res = await c.request('POST', '/signup', { form: { _csrf: t, username: 'a', email: 'nope', password: 'short', confirm: 'x' } });
  assert.equal(res.status, 422);
  assert.match(res.text, /Use 3–20 letters/);
  assert.match(res.text, /valid email/);

  res = await c.request('POST', '/signup', { form: { username: 'valid_name', email: 'a@b.co', password: 'longenough1', confirm: 'longenough1' } });
  assert.equal(res.status, 403);
});

let ada; // logged-in client reused below
test('signup, edit profile with avatar, view profile', async () => {
  ada = client();
  const t = await ada.token('/signup?username=ada_l');
  let res = await ada.request('POST', '/signup', { form: { _csrf: t, ...creds, confirm: creds.password } });
  assert.equal(res.status, 302);
  assert.equal(res.location, '/profile/edit');

  const t2 = await ada.token('/profile/edit');
  const fd = multipartBody(
    { _csrf: t2, display_name: 'Ada Lovelace', headline: 'Analyst', bio: 'Hello <script>alert(1)</script>', location: 'London', website: 'example.com', github: 'https://github.com/adal', linkedin: '', is_public: 'on' },
    { data: PNG, type: 'image/png', name: 'me.png' }
  );
  res = await ada.request('POST', '/profile/edit', { multipart: fd });
  assert.equal(res.status, 302, res.text.slice(0, 300));
  assert.equal(res.location, '/u/ada_l');

  res = await ada.request('GET', '/u/ada_l');
  assert.equal(res.status, 200);
  assert.match(res.text, /Ada Lovelace/);
  assert.match(res.text, /src="\/uploads\/[a-f0-9]{32}\.png"/);
  assert.match(res.text, /https:\/\/example\.com\//);
  assert.match(res.text, /github\.com\/adal/);
  assert.ok(!res.text.includes('<script>alert(1)</script>'), 'bio must be escaped');
  assert.match(res.text, /&lt;script&gt;/);
});

test('uploaded avatar is served', async () => {
  const res = await fetch(base + '/u/ada_l');
  const src = (await res.text()).match(/src="(\/uploads\/[^"]+)"/)[1];
  const img = await fetch(base + src);
  assert.equal(img.status, 200);
  assert.equal(img.headers.get('content-type'), 'image/png');
});

test('fake image is rejected by content check', async () => {
  const t = await ada.token('/profile/edit');
  const fd = multipartBody(
    { _csrf: t, display_name: 'Ada Lovelace', is_public: 'on' },
    { data: Buffer.from('<?php echo 1; ?>'), type: 'image/png', name: 'x.png' }
  );
  const res = await ada.request('POST', '/profile/edit', { multipart: fd });
  assert.equal(res.status, 422);
  assert.match(res.text, /not a valid PNG, JPG, or WebP/);
});

test('oversized and wrong-type uploads show friendly errors', async () => {
  const t = await ada.token('/profile/edit');
  let res = await ada.request('POST', '/profile/edit', {
    multipart: multipartBody({ _csrf: t, display_name: 'Ada' }, { data: Buffer.alloc(2.5 * 1024 * 1024, 1), type: 'image/png', name: 'big.png' }),
  });
  assert.equal(res.status, 422);
  assert.match(res.text, /2 MB or smaller/);

  res = await ada.request('POST', '/profile/edit', {
    multipart: multipartBody({ _csrf: t, display_name: 'Ada' }, { data: Buffer.from('hi'), type: 'text/plain', name: 'a.txt' }),
  });
  assert.equal(res.status, 422);
  assert.match(res.text, /PNG, JPG, or WebP/);
});

test('profile validation errors keep the form filled in', async () => {
  const t = await ada.token('/profile/edit');
  const res = await ada.request('POST', '/profile/edit', {
    multipart: multipartBody({ _csrf: t, display_name: '', website: 'javascript:alert(1)', github: '-bad-', is_public: 'on' }),
  });
  assert.equal(res.status, 422);
  assert.match(res.text, /Enter a name up to 50/);
  assert.match(res.text, /valid web address/);
  assert.match(res.text, /GitHub username/);
});

test('directory lists public profiles and search works', async () => {
  const c = client();
  let res = await c.request('GET', '/');
  assert.match(res.text, /Ada Lovelace/);
  res = await c.request('GET', '/?q=analyst');
  assert.match(res.text, /Ada Lovelace/);
  res = await c.request('GET', '/?q=zzzz%25');
  assert.match(res.text, /No public profiles match/);
});

test('private profile is hidden from others but not the owner', async () => {
  const t = await ada.token('/profile/edit');
  let res = await ada.request('POST', '/profile/edit', { multipart: multipartBody({ _csrf: t, display_name: 'Ada Lovelace' }) });
  assert.equal(res.status, 302);

  const anon = client();
  assert.equal((await anon.request('GET', '/u/ada_l')).status, 404);
  assert.ok(!(await anon.request('GET', '/')).text.includes('Ada Lovelace'));

  res = await ada.request('GET', '/u/ada_l');
  assert.equal(res.status, 200);
  assert.match(res.text, /Only you can see this profile/);
});

test('auth guard redirects and login flow', async () => {
  const anon = client();
  let res = await anon.request('GET', '/profile/edit');
  assert.equal(res.status, 302);
  assert.equal(res.location, '/login');

  let t = await anon.token('/login');
  res = await anon.request('POST', '/login', { form: { _csrf: t, identifier: 'ada_l', password: 'wrong password' } });
  assert.equal(res.status, 401);

  t = await anon.token('/login');
  res = await anon.request('POST', '/login', { form: { _csrf: t, identifier: 'ADA@example.com', password: creds.password } });
  assert.equal(res.status, 302);
  assert.equal(res.location, '/profile/edit'); // returnTo from the guard

  res = await anon.request('GET', '/profile/edit');
  assert.equal(res.status, 200);
});

test('duplicate username and email are rejected', async () => {
  const c = client();
  const t = await c.token('/signup');
  let res = await c.request('POST', '/signup', { form: { _csrf: t, username: 'ADA_L', email: 'other@example.com', password: 'longenough1', confirm: 'longenough1' } });
  assert.equal(res.status, 422);
  assert.match(res.text, /taken/);
  res = await c.request('POST', '/signup', { form: { _csrf: t, username: 'someone', email: 'Ada@Example.com', password: 'longenough1', confirm: 'longenough1' } });
  assert.equal(res.status, 422);
  assert.match(res.text, /already uses this email/);
});

test('password change signs out other devices', async () => {
  const other = client();
  let t = await other.token('/login');
  await other.request('POST', '/login', { form: { _csrf: t, identifier: 'ada_l', password: creds.password } });
  assert.equal((await other.request('GET', '/account')).status, 200);

  t = await ada.token('/account');
  let res = await ada.request('POST', '/account/password', { form: { _csrf: t, current_password: 'nope', new_password: 'new password 123', confirm_password: 'new password 123' } });
  assert.equal(res.status, 422);
  res = await ada.request('POST', '/account/password', { form: { _csrf: t, current_password: creds.password, new_password: 'new password 123', confirm_password: 'new password 123' } });
  assert.equal(res.status, 302);

  assert.equal((await ada.request('GET', '/account')).status, 200, 'current device stays signed in');
  assert.equal((await other.request('GET', '/account')).status, 302, 'other device signed out');
  creds.password = 'new password 123';
});

test('email change requires the current password', async () => {
  const t = await ada.token('/account');
  let res = await ada.request('POST', '/account/email', { form: { _csrf: t, email: 'new@example.com', current_password: 'bad' } });
  assert.equal(res.status, 422);
  res = await ada.request('POST', '/account/email', { form: { _csrf: t, email: 'new@example.com', current_password: creds.password } });
  assert.equal(res.status, 302);
});

test('logout ends the session', async () => {
  const t = await ada.token('/account');
  let res = await ada.request('POST', '/logout', { form: { _csrf: t } });
  assert.equal(res.status, 302);
  res = await ada.request('GET', '/account');
  assert.equal(res.status, 302);
  assert.equal(res.location, '/login');
});

test('account deletion removes profile and avatar', async () => {
  const c = client();
  let t = await c.token('/login');
  await c.request('POST', '/login', { form: { _csrf: t, identifier: 'ada_l', password: creds.password } });
  const uploads = () => fs.readdirSync(path.join(process.env.DATA_DIR, 'uploads'));
  assert.equal(uploads().length, 1, 'only the saved avatar should be on disk');

  t = await c.token('/account');
  let res = await c.request('POST', '/account/delete', { form: { _csrf: t, confirm_username: 'wrong', current_password: creds.password } });
  assert.equal(res.status, 422);
  res = await c.request('POST', '/account/delete', { form: { _csrf: t, confirm_username: 'ada_l', current_password: creds.password } });
  assert.equal(res.status, 200);
  assert.match(res.text, /account is deleted/);
  assert.equal(uploads().length, 0, 'avatar file removed');
  assert.equal((await client().request('GET', '/u/ada_l')).status, 404);
});
