const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'support', 'help', 'about', 'api', 'me',
  'login', 'logout', 'signup', 'register', 'account', 'profile', 'settings',
  'edit', 'u', 'uploads', 'static', 'public', 'css', 'js', 'null', 'undefined',
]);

const USERNAME_RE = /^[a-z0-9_]{3,20}$/i;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const GITHUB_RE = /^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i;
const LINKEDIN_RE = /^[a-z0-9-]{3,100}$/i;

/** Collapse a form value into a trimmed string (never undefined/array). */
function str(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function username(value) {
  if (!USERNAME_RE.test(value)) return 'Use 3–20 letters, numbers, or underscores.';
  if (RESERVED_USERNAMES.has(value.toLowerCase())) return 'That name is reserved. Pick another.';
  return null;
}

function email(value) {
  if (value.length > 254 || !EMAIL_RE.test(value)) return 'Enter a valid email address.';
  return null;
}

function password(value) {
  if (value.length < 8) return 'Use at least 8 characters.';
  // bcrypt only reads the first 72 bytes; refuse rather than silently truncate.
  if (Buffer.byteLength(value, 'utf8') > 72) return 'Use 72 bytes or fewer (about 72 characters).';
  return null;
}

/** Returns a normalized http(s) URL string, '' for empty, or null if invalid. */
function url(value) {
  if (!value) return '';
  if (value.length > 200) return null;
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    if (!parsed.hostname.includes('.')) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

/** Strip a pasted profile URL or leading @ down to the bare handle. */
function handleFrom(value, hostPattern) {
  return value
    .replace(new RegExp(`^(https?://)?(www\\.)?${hostPattern}/`, 'i'), '')
    .replace(/^@/, '')
    .replace(/\/+$/, '');
}

function github(value) {
  const handle = handleFrom(value, 'github\\.com');
  if (!handle) return '';
  return GITHUB_RE.test(handle) ? handle : null;
}

function linkedin(value) {
  const handle = handleFrom(value, 'linkedin\\.com/in');
  if (!handle) return '';
  return LINKEDIN_RE.test(handle) ? handle : null;
}

/** Escape LIKE wildcards so search text is matched literally. */
function likeEscape(value) {
  return value.replace(/[\\%_]/g, (c) => `\\${c}`);
}

module.exports = { str, username, email, password, url, github, linkedin, likeEscape };
