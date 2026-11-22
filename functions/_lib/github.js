const API = 'https://api.github.com';

function headers(env, extra = {}) {
  return {
    authorization: `Bearer ${env.GITHUB_TOKEN}`,
    accept: 'application/vnd.github+json',
    'x-github-api-version': '2022-11-28',
    'user-agent': 'POWER-LINE-Cloudflare-Pages',
    ...extra
  };
}

function repo(env) {
  const owner = String(env.GITHUB_OWNER || '').trim();
  const name = String(env.GITHUB_REPO || '').trim();

  if (!owner || !name || !env.GITHUB_TOKEN) {
    throw new Error('GitHub storage is not configured.');
  }

  return `${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;
}

async function request(url, env, options = {}) {
  const r = await fetch(url, {
    ...options,
    headers: headers(env, options.headers || {})
  });

  let data = {};
  try {
    data = await r.json();
  } catch {}

  if (!r.ok) {
    throw new Error(data.message || `GitHub API error (${r.status})`);
  }

  return data;
}

export async function createPluginRelease(
  env,
  { id, name, description, version, status }
) {
  const path = `${API}/repos/${repo(env)}/releases`;

  return request(path, env, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      tag_name: `power-line-${id}`,
      name: `${name} v${version}`,
      body: description,
      draft: true,
      prerelease: status === 'pre-release'
    })
  });
}

export async function uploadReleaseAsset(
  env,
  release,
  file,
  filename,
  contentType
) {
  const base = release.upload_url.split('{')[0];
  const url = `${base}?name=${encodeURIComponent(filename)}`;
  const bytes = await file.arrayBuffer();

  return request(url, env, {
    method: 'POST',
    headers: {
      'content-type': contentType,
      'content-length': String(bytes.byteLength)
    },
    body: bytes
  });
}

export async function setReleaseStatus(env, id, status) {
  return request(
    `${API}/repos/${repo(env)}/releases/${id}`,
    env,
    {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        draft: status === 'draft',
        prerelease: status === 'pre-release'
      })
    }
  );
}

export async function editPluginRelease(
  env,
  id,
  { name, description, version }
) {
  return request(
    `${API}/repos/${repo(env)}/releases/${id}`,
    env,
    {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: `${name} v${version}`,
        body: description
      })
    }
  );
}

export async function deletePluginRelease(env, id) {
  return request(
    `${API}/repos/${repo(env)}/releases/${id}`,
    env,
    {
      method: 'DELETE'
    }
  );
    }
