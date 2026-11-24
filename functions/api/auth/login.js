 import {
  json,
  sha256,
  verifyPassword,
  randomToken,
  setCookie,
  sameOrigin
} from '../../_lib/auth.js';

function inspectHash(value) {
  try {
    const parts = value.split('$');

    const [scheme, iterations, salt, expected] = parts;

    const decode = (v) => {
      let s = v.replace(/-/g, '+').replace(/_/g, '/');
      s += '='.repeat((4 - s.length % 4) % 4);
      return Uint8Array.from(atob(s), c => c.charCodeAt(0));
    };

    const saltBytes = decode(salt);
    const hashBytes = decode(expected);

    return {
      formatValid:
        parts.length === 4 &&
        scheme === 'pbkdf2' &&
        Number.isInteger(Number(iterations)) &&
        Number(iterations) === 210000 &&
        saltBytes.length === 16 &&
        hashBytes.length === 32,
      schemeValid: scheme === 'pbkdf2',
      iterationsValid: Number(iterations) === 210000,
      saltLengthValid: saltBytes.length === 16,
      hashLengthValid: hashBytes.length === 32
    };
  } catch {
    return {
      formatValid: false,
      schemeValid: false,
      iterationsValid: false,
      saltLengthValid: false,
      hashLengthValid: false
    };
  }
}

export async function onRequestPost({ request, env }) {
  if (!sameOrigin(request)) {
    return json({ message: 'Invalid request origin.' }, 403);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({ message: 'Invalid request.' }, 400);
  }

  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');

  const ownerEmail = String(env.OWNER_EMAIL || '')
    .trim()
    .toLowerCase();

  const storedHash = String(env.OWNER_PASSWORD_HASH || '').trim();

  if (!ownerEmail || !storedHash) {
    return json({ message: 'Owner credentials are not configured.' }, 503);
  }

  if (email !== ownerEmail) {
    return json({ message: 'Owner email does not match.' }, 401);
  }

  const diagnostics = inspectHash(storedHash);

  if (!diagnostics.formatValid) {
    return json({
      message: 'Password hash format is invalid.',
      diagnostics
    }, 500);
  }

  const passwordValid = await verifyPassword(password, storedHash);

  if (!passwordValid) {
    return json({
      message: 'Password verification failed.',
      diagnostics
    }, 401);
  }

  if (!env.DB) {
    return json({ message: 'Database is not configured.' }, 503);
  }

  try {
    const token = randomToken();
    const hash = await sha256(token);
    const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;

    await env.DB.prepare(
      'INSERT INTO sessions(token_hash, expires_at) VALUES(?,?)'
    ).bind(hash, expires).run();

    return new Response(JSON.stringify({ owner: true }), {
      headers: {
        'content-type': 'application/json',
        'cache-control': 'no-store',
        'set-cookie': setCookie(token, 7 * 24 * 60 * 60)
      }
    });
  } catch {
    return json({ message: 'Session creation failed.' }, 500);
  }
}
