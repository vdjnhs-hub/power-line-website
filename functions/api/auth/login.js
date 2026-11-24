 
import {
  json,
  sha256,
  verifyPassword,
  randomToken,
  setCookie,
  sameOrigin
} from '../../_lib/auth.js';

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
    return json({
      message: 'Owner credentials are not configured.'
    }, 503);
  }

  if (email !== ownerEmail) {
    return json({
      message: 'Owner email does not match.'
    }, 401);
  }

  let passwordValid = false;

  try {
    passwordValid = await verifyPassword(password, storedHash);
  } catch {
    return json({
      message: 'Password verification error.'
    }, 500);
  }

  if (!passwordValid) {
    return json({
      message: 'Owner password verification failed.'
    }, 401);
  }

  if (!env.DB) {
    return json({
      message: 'Database is not configured.'
    }, 503);
  }

  try {
    const token = randomToken();
    const hash = await sha256(token);
    const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;

    await env.DB.prepare(
      'INSERT INTO sessions(token_hash, expires_at) VALUES(?,?)'
    ).bind(hash, expires).run();

    return new Response(
      JSON.stringify({ owner: true }),
      {
        headers: {
          'content-type': 'application/json',
          'cache-control': 'no-store',
          'set-cookie': setCookie(token, 7 * 24 * 60 * 60)
        }
      }
    );
  } catch {
    return json({
      message: 'Session creation failed.'
    }, 500);
  }
}
