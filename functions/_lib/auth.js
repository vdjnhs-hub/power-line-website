 
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

  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function decodeBase64Url(value) {
  let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  base64 += '='.repeat((4 - base64.length % 4) % 4);

  return Uint8Array.from(
    atob(base64),
    c => c.charCodeAt(0)
  );
}

export async function verifyPassword(password, stored) {
  try {
    const parts = stored.split('$');

    if (parts.length !== 4) return false;

    const [scheme, iterationsText, salt, expected] = parts;
    const iterations = Number(iterationsText);

    if (
      scheme !== 'pbkdf2' ||
      !Number.isSafeInteger(iterations) ||
      iterations < 1 ||
      !salt ||
      !expected
    ) {
      return false;
    }

    const saltBytes = decodeBase64Url(salt);
    const expectedBytes = decodeBase64Url(expected);

    if (
      saltBytes.length !== 16 ||
      expectedBytes.length !== 32
    ) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations,
        hash: 'SHA-256'
      },
      key,
      256
    );

    const actualBytes = new Uint8Array(bits);

    let difference = 0;

    for (let i = 0; i < actualBytes.length; i++) {
      difference |= actualBytes[i] ^ expectedBytes[i];
    }

    return difference === 0;
  } catch (error) {
    console.error('Password verification error:', error);
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

  const item = cookies.split(';')
    .map(v => v.trim())
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
 
