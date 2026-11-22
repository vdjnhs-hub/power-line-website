 
const COOKIE_NAME = 'pl_session';

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store'
    }
  });
}

export async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function decodeBase64Url(value) {
  let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  base64 += '='.repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export async function verifyPassword(password, stored) {
  try {
    const [scheme, iterations, salt, expected] = stored.split('$');
    if (scheme !== 'pbkdf2' || !salt || !expected) return false;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: decodeBase64Url(salt),
      iterations: Number(iterations),
      hash: 'SHA-256'
    }, key, 256);

    const actual = new Uint8Array(bits);
    const wanted = decodeBase64Url(expected);

    return actual.length === wanted.length &&
      actual.every((value, index) => value === wanted[index]);
  } catch {
    return false;
  }
}

export function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function setCookie(token, maxAge) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export function cookie(request, name = COOKIE_NAME) {
  const cookies = request.headers.get('Cookie') || '';
  const item = cookies.split(';').map(v => v.trim())
    .find(v => v.startsWith(name + '='));
  return item ? item.slice(name.length + 1) : '';
}

export function sameOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

export async function owner(request, env) {
  try {
    const token = cookie(request);
    if (!token || !env.DB) return false;

    const hash = await sha256(token);
    const session = await env.DB.prepare(
      'SELECT token_hash FROM sessions WHERE token_hash = ? AND expires_at > ? LIMIT 1'
    ).bind(hash, Date.now()).first();

    return !!session;
  } catch {
    return false;
  }
}
